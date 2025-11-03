package certstore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/providers/dns"

	"github.com/fgouteroux/acme-manager/config"
	"github.com/fgouteroux/acme-manager/metrics"
	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/ring"
	"github.com/fgouteroux/acme-manager/storage/vault"
	"github.com/fgouteroux/acme-manager/utils"
)

var (
	AmCertificateRingKey = "collectors/certificate"
	AmChallengeRingKey   = "collectors/challenge"
	AmTokenRingKey       = "collectors/token"
	AmStore              *CertStore
)

type CertStore struct {
	RingConfig ring.AcmeManagerRing
	Logger     log.Logger
}

func SaveResource(logger log.Logger, filepath string, certRes *certificate.Resource) {
	domain := utils.SanitizedDomain(logger, certRes.Domain)
	err := os.WriteFile(filepath+domain+".crt", certRes.Certificate, 0600)
	if err != nil {
		_ = level.Error(logger).Log("err", "Unable to save Certificate for domain %s\n\t%v", err)
	}

	if certRes.IssuerCertificate != nil {
		err = os.WriteFile(filepath+domain+".issuer.crt", certRes.IssuerCertificate, 0600)
		if err != nil {
			_ = level.Error(logger).Log("err", "Unable to save IssuerCertificate for domain %s\n\t%v", err)
		}
	}
}

func CreateRemoteCertificateResource(certData *models.Certificate, logger log.Logger) (*models.Certificate, error) {
	vaultSecretPath := fmt.Sprintf("%s/%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Owner, certData.Issuer, certData.Domain)
	domain := utils.SanitizedDomain(logger, certData.Domain)

	baseCertificateFilePath := fmt.Sprintf("%s/%s/%s/%s/", config.GlobalConfig.Common.RootPathCertificate, certData.Owner, certData.Issuer, domain)
	err := utils.CreateNonExistingFolder(baseCertificateFilePath, 0750)
	if err != nil {
		return certData, err
	}

	csrDecoded, err := base64.StdEncoding.DecodeString(certData.Csr)
	if err != nil {
		return certData, err
	}

	csr, err := certcrypto.PemDecodeTox509CSR([]byte(csrDecoded))
	if err != nil {
		return certData, err
	}

	request := certificate.ObtainForCSRRequest{
		CSR:    csr,
		Bundle: certData.Bundle,
	}

	if certData.Days != 0 {
		request.NotAfter = time.Now().Add(time.Duration(certData.Days) * 24 * time.Hour)
	}

	var issuerAcmeClient *lego.Client
	var issuerFound bool
	if issuerAcmeClient, issuerFound = AcmeClient[certData.Issuer]; !issuerFound {
		return certData, fmt.Errorf("could not create certificate domain %s, issuer %s not found", certData.Domain, certData.Issuer)
	}

	var dnsChallenge, httpChallenge string
	if certData.DnsChallenge != "" {
		dnsChallenge = certData.DnsChallenge
	}

	if certData.HttpChallenge != "" {
		httpChallenge = certData.HttpChallenge
	}

	// set challenge from issuer config
	if dnsChallenge == "" && httpChallenge == "" {
		dnsChallenge = config.GlobalConfig.Issuer[certData.Issuer].DNSChallenge
		httpChallenge = config.GlobalConfig.Issuer[certData.Issuer].HTTPChallenge
	}

	var challengeType string
	if dnsChallenge != "" && httpChallenge != "" {
		// this should not happen
		return certData, fmt.Errorf("both DNS (%s) and HTTP (%s) challenges are configured for domain %s", dnsChallenge, httpChallenge, certData.Domain)
	} else if dnsChallenge != "" {
		challengeType = "dns"
	} else if httpChallenge != "" {
		challengeType = "http"
	} else {
		return certData, fmt.Errorf("no challenge method  domain %s, issuer %s", certData.Domain, certData.Issuer)
	}

	// Log the selected challenge
	_ = level.Info(logger).Log(
		"msg", "Challenge method selected",
		"challenge_type", challengeType,
		"provider", map[string]string{"dns": dnsChallenge, "http": httpChallenge}[challengeType],
		"domain", certData.Domain,
		"issuer", certData.Issuer,
		"user", certData.Owner,
	)

	if challengeType == "dns" {
		dnsProvider, err := dns.NewDNSChallengeProviderByName(dnsChallenge)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return certData, err
		}

		dnsResolvers := os.Getenv("ACME_MANAGER_DNS_RESOLVERS")
		dnsPropagationDisableANS := env.GetOrDefaultBool("ACME_MANAGER_DNS_PROPAGATIONDISABLEANS", false)
		dnsPropagationRNS := env.GetOrDefaultBool("ACME_MANAGER_DNS_PROPAGATIONRNS", false)
		dnsPropagationWait := env.GetOrDefaultInt("ACME_MANAGER_DNS_PROPAGATIONWAIT", 0)
		dnsTimeout := env.GetOrDefaultInt("ACME_MANAGER_DNS_TIMEOUT", 10)

		wait := time.Duration(dnsPropagationWait) * time.Second
		if wait < 0 {
			err := fmt.Errorf("env var'ACME_MANAGER_DNS_PROPAGATIONWAIT' cannot be negative")
			_ = level.Error(logger).Log("err", err)
			return certData, err
		}

		err = checkPropagationExclusiveOptions(dnsPropagationDisableANS, dnsPropagationRNS, wait)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return certData, err
		}

		err = issuerAcmeClient.Challenge.SetDNS01Provider(dnsProvider,
			dns01.CondOption(dnsResolvers != "",
				dns01.AddRecursiveNameservers(dns01.ParseNameservers(strings.Split(dnsResolvers, ","))),
			),
			dns01.CondOption(dnsPropagationDisableANS,
				dns01.DisableAuthoritativeNssPropagationRequirement(),
			),
			dns01.CondOption(wait > 0,
				dns01.PropagationWait(wait, true),
			),
			dns01.CondOption(dnsPropagationRNS,
				dns01.RecursiveNSsPropagationRequirement(),
			),
			dns01.CondOption(dnsTimeout > 0,
				dns01.AddDNSTimeout(time.Duration(dnsTimeout)*time.Second),
			),
		)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return certData, err
		}
	}

	if challengeType == "http" {
		httpProvider, err := NewHTTPChallengeProviderByName(httpChallenge, "", logger)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return certData, err
		}

		err = issuerAcmeClient.Challenge.SetHTTP01Provider(httpProvider)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return certData, err
		}
	}

	// build all domains in order to validate each domain in plugins
	certDomains := certData.Domain
	if certData.San != "" {
		certDomains = certDomains + "," + certData.San
	}

	// exec plugins
	for _, plugin := range config.GlobalConfig.Common.Plugins {
		if (plugin.Checksum != "" && slices.Contains(config.SecuredPlugins, plugin.Name)) || plugin.Checksum == "" {
			err = executeCommand(logger, plugin.Path, []string{certDomains, certData.Issuer, challengeType}, plugin.Timeout, plugin.Env)
			if err != nil {
				metrics.SetCreatedCertificate(certData.Issuer, certData.Owner, certData.Domain, 0)
				return certData, err
			}
		}
	}

	resource, err := issuerAcmeClient.Certificate.ObtainForCSR(request)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		metrics.SetCreatedCertificate(certData.Issuer, certData.Owner, certData.Domain, 0)
		return certData, err
	}

	metrics.SetCreatedCertificate(certData.Issuer, certData.Owner, certData.Domain, 1)

	// save in local in case of vault failure
	SaveResource(logger, baseCertificateFilePath, resource)

	x509Cert, err := certcrypto.ParsePEMCertificate(resource.Certificate)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return certData, err
	}

	// Determine the key type and calculate length
	var publicKeyLength int
	switch pubKey := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		publicKeyLength = pubKey.N.BitLen()
	case *ecdsa.PublicKey:
		publicKeyLength = pubKey.Curve.Params().BitSize
	default:
		_ = level.Error(logger).Log("err", "unsupported public key algorithm")
	}

	certData.Encryption = fmt.Sprintf("%s-%d", x509Cert.PublicKeyAlgorithm.String(), publicKeyLength)
	certData.Serial = x509Cert.SerialNumber.Text(16)
	certData.Expires = x509Cert.NotAfter.String()
	certData.Fingerprint = utils.GenerateFingerprint(resource.Certificate)

	renewalDays := config.GlobalConfig.Common.CertDaysRenewal
	if certData.RenewalDays != "" {
		renewalDays = certData.RenewalDays
	}
	certRenewalDays := strings.Split(renewalDays, "-")
	var certRenewalMinDays, certRenewalMaxDays int
	if len(certRenewalDays) != 2 {
		certRenewalMinDays, _ = strconv.Atoi(certRenewalDays[0])
		certRenewalMaxDays, _ = strconv.Atoi(certRenewalDays[0])
	} else {
		certRenewalMinDays, _ = strconv.Atoi(certRenewalDays[0])
		certRenewalMaxDays, _ = strconv.Atoi(certRenewalDays[1])
	}

	certData.RenewalDate = utils.RandomWeekdayBeforeExpiration(x509Cert.NotAfter, certRenewalMinDays, certRenewalMaxDays).String()

	data := models.CertMap{
		Certificate: certData,
		Cert:        string(resource.Certificate),
		CAIssuer:    string(resource.IssuerCertificate),
		URL:         resource.CertStableURL,
	}

	err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return certData, err
	}
	_ = level.Info(logger).Log("msg", "Certificate saved to vault", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)

	// remove local cert once stored in vault
	err = os.RemoveAll(baseCertificateFilePath)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
	}

	return certData, nil
}

func DeleteRemoteCertificateResource(certData *models.Certificate, logger log.Logger) error {
	vaultSecretPath := fmt.Sprintf("%s/%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Owner, certData.Issuer, certData.Domain)
	data, err := vault.GlobalClient.GetSecretWithAppRole(vaultSecretPath)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return err
	}

	if certBytes, ok := data["cert"]; ok {
		var issuerAcmeClient *lego.Client
		var issuerFound bool
		if issuerAcmeClient, issuerFound = AcmeClient[certData.Issuer]; !issuerFound {
			return fmt.Errorf("could not delete certificate domain %s, issuer %s not found", certData.Domain, certData.Issuer)
		}

		err = issuerAcmeClient.Certificate.Revoke([]byte(certBytes.(string)))
		if err != nil &&
			!strings.Contains(err.Error(), "Certificate is expired") &&
			!strings.Contains(err.Error(), "urn:ietf:params:acme:error:alreadyRevoked") {
			_ = level.Error(logger).Log("err", err)
			metrics.SetRevokedCertificate(certData.Issuer, certData.Owner, certData.Domain, 0)
			return err
		}

		metrics.SetRevokedCertificate(certData.Issuer, certData.Owner, certData.Domain, 1)

		err = vault.GlobalClient.DeleteSecretWithAppRole(vaultSecretPath)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return err
		}
	} else {
		_ = level.Error(logger).Log("err", fmt.Errorf("no cert found in vault secret key: %s", vaultSecretPath))
	}
	return nil
}

func CheckCertExpiration(amStore *CertStore, logger log.Logger) error {
	data, err := amStore.ListAllCertificates()
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return err
	}

	for _, certData := range data {
		if certData.DeletedAt > 0 {
			continue
		}

		layout := "2006-01-02 15:04:05 -0700 MST"
		renewalDate, err := time.Parse(layout, certData.RenewalDate)
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to parse renewal date for certificate owner '%s', issuer '%s' and domain '%s'", certData.Owner, certData.Issuer, certData.Domain))
			continue
		}

		currentDate := time.Now()
		if currentDate.After(renewalDate) || currentDate.Equal(renewalDate) {
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Trying renewal certificate owner '%s', issuer '%s' and domain '%s'", certData.Owner, certData.Issuer, certData.Domain))
			cert, err := CreateRemoteCertificateResource(certData, logger)
			if err != nil {
				metrics.SetRenewedCertificate(cert.Issuer, cert.Owner, cert.Domain, 0)
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to renew certificate owner '%s', issuer '%s' and domain '%s'", certData.Owner, certData.Issuer, certData.Domain), "err", err)
				continue
			}
			err = amStore.PutCertificate(cert)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				metrics.SetRenewedCertificate(cert.Issuer, cert.Owner, cert.Domain, 0)
				continue
			}
			metrics.SetRenewedCertificate(cert.Issuer, cert.Owner, cert.Domain, 1)
			// Reset the created metric to ensure consistency (successful renewal means no creation issues)
			metrics.SetCreatedCertificate(cert.Issuer, cert.Owner, cert.Domain, 1)
		}
	}
	return nil
}

func MapInterfaceToCertMap(data map[string]interface{}) models.CertMap {
	val, _ := json.Marshal(data)
	var result models.CertMap
	_ = json.Unmarshal(val, &result)
	return result
}

func checkPropagationExclusiveOptions(dnsPropagationDisableANS, dnsPropagationRNS bool, dnsPropagationWait time.Duration) error {
	if dnsPropagationDisableANS && dnsPropagationWait > 0 {
		return fmt.Errorf("env var 'ACME_MANAGER_DNS_PROPAGATIONDISABLEANS' and 'ACME_MANAGER_DNS_PROPAGATIONWAIT' are mutually exclusive")
	}

	if dnsPropagationRNS && dnsPropagationWait > 0 {
		return fmt.Errorf("env var 'ACME_MANAGER_DNS_PROPAGATIONRNS' and 'ACME_MANAGER_DNS_PROPAGATIONWAIT' are mutually exclusive")
	}
	return nil
}

func executeCommand(logger log.Logger, cmdPath string, cmdArgs []string, cmdTimeout int, envVars map[string]string) error {
	if cmdPath == "" {
		return fmt.Errorf("cmdPath is empty")
	}

	// Set default timeout
	if cmdTimeout == 0 {
		cmdTimeout = 60
	}

	run := func(cmdPath string, cmdArgs []string, cmdTimeout int, envVars map[string]string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cmdTimeout)*time.Second)
		defer cancel()

		var out bytes.Buffer

		cmd := exec.CommandContext(ctx, cmdPath, cmdArgs...)
		cmd.Stdout = &out
		cmd.Stderr = &out

		// Set environment variables
		cmd.Env = cmd.Environ() // Inherit the current process environment
		for key, value := range envVars {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
		}

		err := cmd.Run()
		return out.String(), err
	}

	out, err := run(cmdPath, cmdArgs, cmdTimeout, envVars)
	if err != nil {
		return fmt.Errorf("command '%s %s' failed: %s. Error: %s", cmdPath, strings.Join(cmdArgs, " "), out, err.Error())
	}
	_ = level.Info(logger).Log("msg", fmt.Sprintf("Command '%s %s' successfully executed", cmdPath, strings.Join(cmdArgs, " ")))
	_ = level.Debug(logger).Log("msg", "Command output", "output", out)

	return nil
}
