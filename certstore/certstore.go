package certstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/grafana/dskit/kv/memberlist"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/providers/dns"

	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/cmd"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/memcache"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"
)

var (
	AmRingKey          = "collectors/cert"
	AmRingChallengeKey = "collectors/challenge"
	certConfig         cert.Config
	localCache         = memcache.NewLocalCache()
	AmStore            *CertStore
)

type CertStore struct {
	RingConfig ring.AcmeManagerRing
	Logger     log.Logger
	lock       sync.Mutex
}

func (c *CertStore) GetKVRingCert(key string) ([]cert.Certificate, error) {
	var data []cert.Certificate

	content, err := c.GetKVRing(key)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to get kv store key '%s'", key), "err", err)
		return data, err
	}

	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err)
		return data, err
	}
	return data, nil
}

func (c *CertStore) GetKVRingTokenChallenge(key string) (map[string]string, error) {
	var data map[string]string
	content, err := c.GetKVRing(key)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to get kv store key '%s'", key), "err", err)
		return data, err
	}

	if content != "" {
		err = json.Unmarshal([]byte(content), &data)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err)
			return data, err
		}
	}
	return data, nil
}

func (c *CertStore) GetKVRing(key string) (string, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	var data string

	ctx := context.Background()
	cached, err := c.RingConfig.JSONClient.Get(ctx, key)
	if err != nil {
		return data, err
	}

	if cached != nil {
		data = cached.(*ring.Data).Content
	}
	return data, nil
}

func (c *CertStore) PutKVRing(key string, data interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	_ = level.Info(c.Logger).Log("msg", fmt.Sprintf("Updating kv store key '%s'", key))

	content, _ := json.Marshal(data)
	c.updateKV(key, string(content))
}

func (c *CertStore) updateKV(key, content string) {
	data := &ring.Data{
		Content:   content,
		CreatedAt: time.Now(),
	}

	val, err := ring.JSONCodec.Encode(data)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to encode data with '%s'", ring.JSONCodec.CodecID()), "err", err)
		return
	}

	msg := memberlist.KeyValuePair{
		Key:   key,
		Value: val,
		Codec: ring.JSONCodec.CodecID(),
	}

	msgBytes, _ := msg.Marshal()
	c.RingConfig.KvStore.NotifyMsg(msgBytes)
}

func SaveResource(logger log.Logger, filepath string, certRes *certificate.Resource) {
	domain := utils.SanitizedDomain(logger, certRes.Domain)
	err := os.WriteFile(filepath+domain+".crt", certRes.Certificate, config.GlobalConfig.Common.CertKeyFilePerm)
	if err != nil {
		_ = level.Error(logger).Log("err", "Unable to save Certificate for domain %s\n\t%v", err)
	}

	if certRes.IssuerCertificate != nil {
		err = os.WriteFile(filepath+domain+".issuer.crt", certRes.IssuerCertificate, config.GlobalConfig.Common.CertKeyFilePerm)
		if err != nil {
			_ = level.Error(logger).Log("err", "Unable to save IssuerCertificate for domain %s\n\t%v", err)
		}
	}

	if certRes.PrivateKey != nil {
		err = os.WriteFile(filepath+domain+".key", certRes.PrivateKey, config.GlobalConfig.Common.CertKeyFilePerm)
		if err != nil {
			_ = level.Error(logger).Log("err", "Unable to save PrivateKey for domain %s\n\t%v", err)
		}
	}
}

func kvStore(data cert.Certificate, cert, key []byte) (cert.Certificate, error) {
	//Override this key to avoid kvring changes
	data.RenewalDays = 0
	if data.Days == 0 {
		data.Days = config.GlobalConfig.Common.CertDays
	}

	if len(cert) > 0 {
		x509Cert, err := certcrypto.ParsePEMCertificate(cert)
		if err != nil {
			return data, err
		}
		data.Expires = x509Cert.NotAfter.String()
		data.Fingerprint = utils.GenerateFingerprint(cert)
	}

	if len(key) > 0 {
		data.KeyFingerprint = utils.GenerateFingerprint(key)
	}

	return data, nil
}

type mapDiff struct {
	Create   []cert.Certificate `json:"create"`
	Update   []cert.Certificate `json:"update"`
	Delete   []cert.Certificate `json:"delete"`
	Unchange []cert.Certificate `json:"unchange"`
}

func checkCertDiff(old, newCertList []cert.Certificate, logger log.Logger) (mapDiff, bool) {
	var hasChange bool
	var diff mapDiff

	for _, oldCert := range old {
		idx := slices.IndexFunc(newCertList, func(c cert.Certificate) bool {
			return c.Domain == oldCert.Domain && c.Issuer == oldCert.Issuer
		})

		// key to delete
		if idx == -1 {
			hasChange = true
			diff.Delete = append(diff.Delete, oldCert)
			//key to update
		} else if idx >= 0 && oldCert != newCertList[idx] {
			hasChange = true
			diff.Update = append(diff.Update, newCertList[idx])
			// key unchanged
		} else if idx >= 0 {
			diff.Unchange = append(diff.Unchange, oldCert)
		}
	}

	for _, newCert := range newCertList {
		idx := slices.IndexFunc(old, func(c cert.Certificate) bool {
			return c.Domain == newCert.Domain && c.Issuer == newCert.Issuer
		})

		if idx == -1 {
			hasChange = true
			diff.Create = append(diff.Create, newCert)
		}
	}
	diffStr, _ := json.Marshal(diff)

	_ = level.Debug(logger).Log("msg", diffStr)

	return diff, hasChange
}

func applyCertFileChanges(diff mapDiff, logger log.Logger) ([]cert.Certificate, error) {
	var certInfo []cert.Certificate
	var hasChange bool
	certInfo = append(certInfo, diff.Unchange...)

	for _, certData := range diff.Create {
		hasChange = true
		newCert, err := createRemoteCertificateResource(certData, logger)
		if err != nil {
			return certInfo, err
		}
		metrics.IncManagedCertificate(certData.Issuer)
		certInfo = append(certInfo, newCert)

		if config.GlobalConfig.Common.CertDeploy {
			createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
		}
	}

	for _, certData := range diff.Update {
		hasChange = true
		err := deleteRemoteCertificateResource(certData.Domain, certData.Issuer, logger)
		if err != nil {
			return certInfo, err
		}
		if config.GlobalConfig.Common.CertDeploy {
			deletelocalCertificateResource(certData.Domain, certData.Issuer, logger)
		}
		newCert, err := createRemoteCertificateResource(certData, logger)
		if err != nil {
			return certInfo, err
		}
		certInfo = append(certInfo, newCert)
		if config.GlobalConfig.Common.CertDeploy {
			createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
		}
	}

	for _, certData := range diff.Delete {
		hasChange = true
		err := deleteRemoteCertificateResource(certData.Domain, certData.Issuer, logger)
		if err != nil {
			return certInfo, err
		}
		metrics.DecManagedCertificate(certData.Issuer)
		if config.GlobalConfig.Common.CertDeploy {
			deletelocalCertificateResource(certData.Domain, certData.Issuer, logger)
		}
	}

	if hasChange && config.GlobalConfig.Common.CmdEnabled {
		cmd.Execute(logger, config.GlobalConfig)
	}

	return certInfo, nil
}

func applyRingKvStoreChanges(diff mapDiff, logger log.Logger) {
	for _, certData := range diff.Create {
		createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
	}

	for _, certData := range diff.Update {
		createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
	}

	for _, certData := range diff.Delete {
		deletelocalCertificateResource(certData.Domain, certData.Issuer, logger)
	}
}

func createlocalCertificateResource(certName, issuer string, logger log.Logger) {
	err := utils.CreateNonExistingFolder(config.GlobalConfig.Common.CertDir+issuer, config.GlobalConfig.Common.CertDirPerm)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}
	certFilePath := config.GlobalConfig.Common.CertDir + issuer + "/" + certName + ".crt"
	keyFilePath := config.GlobalConfig.Common.CertDir + issuer + "/" + certName + ".key"

	secretKeyPath := config.GlobalConfig.Storage.Vault.SecretPrefix + "/" + issuer + "/" + certName
	secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
	} else if secret == nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("No data found in vault secret key %s", secretKeyPath))
	} else {
		if cert64, ok := secret["cert"]; ok {
			certBytes, _ := base64.StdEncoding.DecodeString(cert64.(string))

			err := os.WriteFile(certFilePath, certBytes, config.GlobalConfig.Common.CertFilePerm)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err)
			} else {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath))
				metrics.IncCreatedLocalCertificate(issuer)
			}
		} else {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("No certificate found in vault secret key %s", secretKeyPath), "err", err)
		}

		if key64, ok := secret["key"]; ok {
			keyBytes, _ := base64.StdEncoding.DecodeString(key64.(string))

			err := os.WriteFile(keyFilePath, keyBytes, config.GlobalConfig.Common.CertKeyFilePerm)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
			} else {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath))
			}
		} else {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("No private key found in vault secret key %s", secretKeyPath), "err", err)
		}
	}
}

func deletelocalCertificateResource(certName, issuer string, logger log.Logger) {
	certFilePath := config.GlobalConfig.Common.CertDir + issuer + "/" + certName + ".crt"
	keyFilePath := config.GlobalConfig.Common.CertDir + issuer + "/" + certName + ".key"

	err := os.Remove(certFilePath)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to delete certificate file %s", certFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Removed certificate %s", certFilePath))
		metrics.IncDeletedLocalCertificate(issuer)
	}

	err = os.Remove(keyFilePath)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to delete private key file %s", keyFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Removed private key %s", keyFilePath))
	}
}

func createRemoteCertificateResource(certData cert.Certificate, logger log.Logger) (cert.Certificate, error) {
	var newCert cert.Certificate
	vaultSecretPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.SecretPrefix, certData.Issuer, certData.Domain)
	domain := utils.SanitizedDomain(logger, certData.Domain)

	baseCertificateFilePath := fmt.Sprintf("%s/%s/%s/", config.GlobalConfig.Common.RootPathCertificate, certData.Issuer, domain)
	err := utils.CreateNonExistingFolder(baseCertificateFilePath, config.GlobalConfig.Common.CertDirPerm)
	if err != nil {
		return newCert, err
	}

	domains := []string{domain}
	if certData.SAN != "" {
		san := strings.Split(strings.TrimSuffix(certData.SAN, ","), ",")
		domains = append(domains, san...)
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  certData.Bundle,
	}

	// let's encrypt doesn't support certificate duration
	// urn:ietf:params:acme:error:malformed :: NotBefore and NotAfter are not supported
	if certData.Issuer != "letsencrypt" {
		if certData.Days != 0 {
			request.NotAfter = time.Now().Add(time.Duration(certData.Days) * 24 * time.Hour)
		} else {
			request.NotAfter = time.Now().Add(time.Duration(config.GlobalConfig.Common.CertDays) * 24 * time.Hour)
		}
	}

	issuerAcmeClient := AcmeClient[certData.Issuer]

	if certData.DNSChallenge != "" {
		dnsProvider, err := dns.NewDNSChallengeProviderByName(certData.DNSChallenge)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return newCert, err
		}

		err = issuerAcmeClient.Challenge.SetDNS01Provider(dnsProvider)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return newCert, err
		}
	}

	if certData.HTTPChallenge != "" {
		httpProvider, err := NewHTTPChallengeProviderByName(certData.HTTPChallenge, "")
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return newCert, err
		}

		err = issuerAcmeClient.Challenge.SetHTTP01Provider(httpProvider)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return newCert, err
		}
	}

	resource, err := issuerAcmeClient.Certificate.Obtain(request)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return newCert, err
	}

	metrics.IncCreatedCertificate(certData.Issuer)

	// save in local in case of vault failure
	SaveResource(logger, baseCertificateFilePath, resource)

	data := map[string]interface{}{
		"cert":   resource.Certificate,
		"key":    resource.PrivateKey,
		"issuer": resource.IssuerCertificate,
	}
	err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, data)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return newCert, err
	}
	// remove local cert once stored in vault
	err = os.RemoveAll(baseCertificateFilePath)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
	}

	newCert, err = kvStore(certData, resource.Certificate, resource.PrivateKey)
	if err != nil {
		return newCert, err
	}

	return newCert, nil
}

func deleteRemoteCertificateResource(name, issuer string, logger log.Logger) error {
	vaultSecretPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.SecretPrefix, issuer, name)
	domain := utils.SanitizedDomain(logger, name)
	data, err := vault.GlobalClient.GetSecretWithAppRole(vaultSecretPath)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return err
	}

	if cert64, ok := data["cert"]; ok {
		certBytes, _ := base64.StdEncoding.DecodeString(cert64.(string))
		err = AcmeClient[issuer].Certificate.Revoke(certBytes)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return err
		}

		metrics.IncRevokedCertificate(issuer)

		_ = level.Info(logger).Log("msg", fmt.Sprintf("Certificate domain %s for %s issuer revoked", domain, issuer))
		err = vault.GlobalClient.DeleteSecretWithAppRole(vaultSecretPath)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return err
		}
	} else {
		_ = level.Error(logger).Log("err", fmt.Errorf("No cert found in vault secret key: %s", vaultSecretPath))
	}
	return nil
}

func CheckAndDeployLocalCertificate(amStore *CertStore, logger log.Logger) error {
	// not deploy certs
	if !config.GlobalConfig.Common.CertDeploy {
		return nil
	}

	data, err := amStore.GetKVRingCert(AmRingKey)
	if err != nil {
		return err
	}

	var hasChange bool
	certStat := make(map[string]float64)
	for _, certData := range data {
		certStat[certData.Issuer] += 1.0
		certFilePath := config.GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
		keyFilePath := config.GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

		certFileExists := utils.FileExists(certFilePath)
		keyFileExists := utils.FileExists(keyFilePath)

		if !certFileExists && !keyFileExists {
			hasChange = true
			createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
		} else {
			var certBytes, keyBytes []byte
			if certFileExists {
				certBytes, err = os.ReadFile(filepath.Clean(certFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err)
				}
			} else {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Certificate file %s doesn't exists", certFilePath))
				err := utils.CreateNonExistingFolder(config.GlobalConfig.Common.CertDir+certData.Issuer, config.GlobalConfig.Common.CertDirPerm)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}
			}

			if keyFileExists {
				keyBytes, err = os.ReadFile(filepath.Clean(keyFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err)
				}
			} else {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Private key file %s doesn't exists", keyFilePath))
				err := utils.CreateNonExistingFolder(config.GlobalConfig.Common.CertDir+certData.Issuer, config.GlobalConfig.Common.CertDirPerm)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}
			}

			var secret map[string]interface{}
			if utils.GenerateFingerprint(certBytes) != certData.Fingerprint {
				hasChange = true
				secretKeyPath := config.GlobalConfig.Storage.Vault.SecretPrefix + "/" + certData.Issuer + "/" + certData.Domain
				secret, err = vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}

				if cert64, ok := secret["cert"]; ok {
					certBytes, _ := base64.StdEncoding.DecodeString(cert64.(string))

					err := os.WriteFile(certFilePath, certBytes, config.GlobalConfig.Common.CertFilePerm)
					if err != nil {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err)
					} else {
						_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath))
					}
				} else {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("No certificate found in vault secret key %s", secretKeyPath), "err", err)
				}
			}

			if utils.GenerateFingerprint(keyBytes) != certData.KeyFingerprint {
				hasChange = true
				secretKeyPath := config.GlobalConfig.Storage.Vault.SecretPrefix + "/" + certData.Issuer + "/" + certData.Domain
				if secret == nil {
					secret, err = vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
					if err != nil {
						_ = level.Error(logger).Log("err", err)
						continue
					}
				}
				if key64, ok := secret["key"]; ok {
					keyBytes, _ := base64.StdEncoding.DecodeString(key64.(string))

					err := os.WriteFile(keyFilePath, keyBytes, config.GlobalConfig.Common.CertKeyFilePerm)
					if err != nil {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
					} else {
						_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath))
					}
				} else {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("No private key found in vault secret key %s", secretKeyPath), "err", err)
				}
			}
		}
	}

	for issuer, count := range certStat {
		metrics.SetManagedCertificate(issuer, count)
	}
	if hasChange && config.GlobalConfig.Common.CmdEnabled {
		cmd.Execute(logger, config.GlobalConfig)
	}
	return nil
}

func CheckCertExpiration(amStore *CertStore, logger log.Logger) error {
	data, err := amStore.GetKVRingCert(AmRingKey)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return err
	}

	dataCopy := make([]cert.Certificate, len(data))
	_ = copy(dataCopy, data)

	var hasChange bool
	for i, certData := range data {
		layout := "2006-01-02 15:04:05 -0700 MST"
		t, err := time.Parse(layout, certData.Expires)
		if err != nil {
			return err
		}

		// This is just meant to be informal for the user.
		timeLeft := t.Sub(time.Now().UTC())

		idx := slices.IndexFunc(certConfig.Certificate, func(c cert.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer
		})

		c := certConfig.Certificate[idx]

		if idx >= 0 {
			if c.RenewalDays == 0 {
				c.RenewalDays = config.GlobalConfig.Common.CertDaysRenewal
			}

			daysLeft := int(timeLeft.Hours()) / 24
			_ = level.Info(logger).Log("msg", fmt.Sprintf("[%s] acme: %d days remaining", certData.Domain, daysLeft))
			if daysLeft < c.RenewalDays {
				hasChange = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf("[%s] acme: Trying renewal with %d days remaining", certData.Domain, daysLeft))
				cert, err := createRemoteCertificateResource(certData, logger)
				if err != nil {
					return err
				}
				metrics.IncRenewedCertificate(certData.Issuer)
				if config.GlobalConfig.Common.CertDeploy {
					deletelocalCertificateResource(certData.Domain, certData.Issuer, logger)

				}
				dataCopy[i] = cert
				if config.GlobalConfig.Common.CertDeploy {
					createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
				}
			}
		} else {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Cannot check certificate renewal because the certificate '%s' is not in config file", certData.Domain))
		}
	}
	if hasChange {
		localCache.Set(AmRingKey, dataCopy)
		amStore.PutKVRing(AmRingKey, dataCopy)

		if config.GlobalConfig.Common.CmdEnabled {
			cmd.Execute(logger, config.GlobalConfig)
		}

	}
	return nil
}

func WatchCertExpiration(logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if isLeaderNow {
			err := CheckCertExpiration(AmStore, logger)
			if err != nil {
				_ = level.Error(logger).Log("msg", "Certificate check renewal failed", "err", err)
			}
		}
	}
}
