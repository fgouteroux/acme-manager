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
		level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to get kv store key '%s'", key), "err", err) // #nosec G104
		return data, err
	}

	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err) // #nosec G104
		return data, err
	}
	return data, nil
}

func (c *CertStore) GetKVRingTokenChallenge(key string) (map[string]string, error) {
	var data map[string]string
	content, err := c.GetKVRing(key)
	if err != nil {
		level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to get kv store key '%s'", key), "err", err) // #nosec G104
		return data, err
	}

	if content != "" {
		err = json.Unmarshal([]byte(content), &data)
		if err != nil {
			level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err) // #nosec G104
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

	level.Info(c.Logger).Log("msg", fmt.Sprintf("Updating kv store key '%s'", key)) // #nosec G104

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
		level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to encode data with '%s'", ring.JSONCodec.CodecID()), "err", err) // #nosec G104
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
	err := os.WriteFile(filepath+domain+".crt", certRes.Certificate, 0600)
	if err != nil {
		level.Error(logger).Log("err", "Unable to save Certificate for domain %s\n\t%v", err) // #nosec G104
	}

	if certRes.IssuerCertificate != nil {
		err = os.WriteFile(filepath+domain+".issuer.crt", certRes.IssuerCertificate, 0600)
		if err != nil {
			level.Error(logger).Log("err", "Unable to save IssuerCertificate for domain %s\n\t%v", err) // #nosec G104
		}
	}

	if certRes.PrivateKey != nil {
		err = os.WriteFile(filepath+domain+".key", certRes.PrivateKey, 0600)
		if err != nil {
			level.Error(logger).Log("err", "Unable to save PrivateKey for domain %s\n\t%v", err) // #nosec G104
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

	level.Debug(logger).Log("msg", diffStr) // #nosec G104

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
	err := utils.CreateNonExistingFolder(config.GlobalConfig.Common.CertDir + issuer)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		return
	}
	certFilePath := config.GlobalConfig.Common.CertDir + issuer + "/" + certName + ".crt"
	keyFilePath := config.GlobalConfig.Common.CertDir + issuer + "/" + certName + ".key"

	secretKeyPath := config.GlobalConfig.Storage.Vault.SecretPrefix + "/" + issuer + "/" + certName
	secret, err := vault.GetSecretWithAppRole(vault.VaultClient, config.GlobalConfig.Storage.Vault, secretKeyPath)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
	} else if secret == nil {
		level.Error(logger).Log("msg", fmt.Sprintf("No data found in vault secret key %s", secretKeyPath)) // #nosec G104
	} else {
		if cert64, ok := secret["cert"]; ok {
			certBytes, _ := base64.StdEncoding.DecodeString(cert64.(string))

			err := os.WriteFile(certFilePath, certBytes, 0600)
			if err != nil {
				level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err) // #nosec G104
			} else {
				level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath)) // #nosec G104
			}
		} else {
			level.Error(logger).Log("msg", fmt.Sprintf("No certificate found in vault secret key %s", secretKeyPath), "err", err) // #nosec G104
		}

		if key64, ok := secret["key"]; ok {
			keyBytes, _ := base64.StdEncoding.DecodeString(key64.(string))

			err := os.WriteFile(keyFilePath, keyBytes, 0600)
			if err != nil {
				level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err) // #nosec G104
			} else {
				level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath)) // #nosec G104
			}
		} else {
			level.Error(logger).Log("msg", fmt.Sprintf("No private key found in vault secret key %s", secretKeyPath), "err", err) // #nosec G104
		}
	}
}

func deletelocalCertificateResource(certName, issuer string, logger log.Logger) {
	certFilePath := config.GlobalConfig.Common.CertDir + issuer + "/" + certName + ".crt"
	keyFilePath := config.GlobalConfig.Common.CertDir + issuer + "/" + certName + ".key"

	err := os.Remove(certFilePath)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("Unable to delete certificate file %s", certFilePath), "err", err) // #nosec G104
	} else {
		level.Info(logger).Log("msg", fmt.Sprintf("Removed certificate %s", certFilePath)) // #nosec G104
	}

	err = os.Remove(keyFilePath)
	if err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("Unable to delete private key file %s", keyFilePath), "err", err) // #nosec G104
	} else {
		level.Info(logger).Log("msg", fmt.Sprintf("Removed private key %s", keyFilePath)) // #nosec G104
	}
}

func createRemoteCertificateResource(certData cert.Certificate, logger log.Logger) (cert.Certificate, error) {
	var newCert cert.Certificate
	vaultSecretPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.SecretPrefix, certData.Issuer, certData.Domain)
	domain := utils.SanitizedDomain(logger, certData.Domain)

	baseCertificateFilePath := fmt.Sprintf("%s/%s/%s/", config.GlobalConfig.Common.RootPathCertificate, certData.Issuer, domain)
	err := utils.CreateNonExistingFolder(baseCertificateFilePath)
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
			level.Error(logger).Log("err", err) // #nosec G104
			return newCert, err
		}

		err = issuerAcmeClient.Challenge.SetDNS01Provider(dnsProvider)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return newCert, err
		}
	}

	if certData.HTTPChallenge != "" {
		httpProvider, err := NewHTTPChallengeProviderByName(certData.HTTPChallenge, "")
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return newCert, err
		}

		err = issuerAcmeClient.Challenge.SetHTTP01Provider(httpProvider)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return newCert, err
		}
	}

	resource, err := issuerAcmeClient.Certificate.Obtain(request)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		return newCert, err
	}

	// save in local in case of vault failure
	SaveResource(logger, baseCertificateFilePath, resource)

	data := map[string]interface{}{
		"cert":   resource.Certificate,
		"key":    resource.PrivateKey,
		"issuer": resource.IssuerCertificate,
	}
	err = vault.PutSecretWithAppRole(vault.VaultClient, config.GlobalConfig.Storage.Vault, vaultSecretPath, data)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		return newCert, err
	}
	// remove local cert once stored in vault
	err = os.RemoveAll(baseCertificateFilePath)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
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
	data, err := vault.GetSecretWithAppRole(vault.VaultClient, config.GlobalConfig.Storage.Vault, vaultSecretPath)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		return err
	}

	if cert64, ok := data["cert"]; ok {
		certBytes, _ := base64.StdEncoding.DecodeString(cert64.(string))
		err = AcmeClient[issuer].Certificate.Revoke(certBytes)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return err
		}

		level.Info(logger).Log("msg", fmt.Sprintf("Certificate domain %s for %s issuer revoked", domain, issuer)) // #nosec G104
		err = vault.DeleteSecretWithAppRole(vault.VaultClient, config.GlobalConfig.Storage.Vault, vaultSecretPath)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return err
		}
	} else {
		level.Error(logger).Log("err", fmt.Errorf("No cert found in vault secret key: %s", vaultSecretPath)) // #nosec G104
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
	for _, certData := range data {
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
					level.Error(logger).Log("err", err) // #nosec G104
				}
			} else {
				level.Error(logger).Log("msg", fmt.Sprintf("Certificate file %s doesn't exists", certFilePath)) // #nosec G104
				err := utils.CreateNonExistingFolder(config.GlobalConfig.Common.CertDir + certData.Issuer)
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
					continue
				}
			}

			if keyFileExists {
				keyBytes, err = os.ReadFile(filepath.Clean(keyFilePath))
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
				}
			} else {
				level.Error(logger).Log("msg", fmt.Sprintf("Private key file %s doesn't exists", keyFilePath)) // #nosec G104
				err := utils.CreateNonExistingFolder(config.GlobalConfig.Common.CertDir + certData.Issuer)
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
					continue
				}
			}

			var secret map[string]interface{}
			if utils.GenerateFingerprint(certBytes) != certData.Fingerprint {
				hasChange = true
				secretKeyPath := config.GlobalConfig.Storage.Vault.SecretPrefix + "/" + certData.Issuer + "/" + certData.Domain
				secret, err = vault.GetSecretWithAppRole(vault.VaultClient, config.GlobalConfig.Storage.Vault, secretKeyPath)
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
					continue
				}

				if cert64, ok := secret["cert"]; ok {
					certBytes, _ := base64.StdEncoding.DecodeString(cert64.(string))

					err := os.WriteFile(certFilePath, certBytes, 0600)
					if err != nil {
						level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err) // #nosec G104
					} else {
						level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath)) // #nosec G104
					}
				} else {
					level.Error(logger).Log("msg", fmt.Sprintf("No certificate found in vault secret key %s", secretKeyPath), "err", err) // #nosec G104
				}
			}

			if utils.GenerateFingerprint(keyBytes) != certData.KeyFingerprint {
				hasChange = true
				secretKeyPath := config.GlobalConfig.Storage.Vault.SecretPrefix + "/" + certData.Issuer + "/" + certData.Domain
				if secret == nil {
					secret, err = vault.GetSecretWithAppRole(vault.VaultClient, config.GlobalConfig.Storage.Vault, secretKeyPath)
					if err != nil {
						level.Error(logger).Log("err", err) // #nosec G104
						continue
					}
				}
				if key64, ok := secret["key"]; ok {
					keyBytes, _ := base64.StdEncoding.DecodeString(key64.(string))

					err := os.WriteFile(keyFilePath, keyBytes, 0600)
					if err != nil {
						level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err) // #nosec G104
					} else {
						level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath)) // #nosec G104
					}
				} else {
					level.Error(logger).Log("msg", fmt.Sprintf("No private key found in vault secret key %s", secretKeyPath), "err", err) // #nosec G104
				}
			}
		}
	}
	if hasChange && config.GlobalConfig.Common.CmdEnabled {
		cmd.Execute(logger, config.GlobalConfig)
	}
	return nil
}

func CheckCertExpiration(amStore *CertStore, logger log.Logger) error {
	data, err := amStore.GetKVRingCert(AmRingKey)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
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
			level.Info(logger).Log("msg", fmt.Sprintf("[%s] acme: %d days remaining", certData.Domain, daysLeft)) // #nosec G104
			if daysLeft < c.RenewalDays {
				hasChange = true
				level.Info(logger).Log("msg", fmt.Sprintf("[%s] acme: Trying renewal with %d days remaining", certData.Domain, daysLeft)) // #nosec G104
				cert, err := createRemoteCertificateResource(certData, logger)
				if err != nil {
					return err
				}
				if config.GlobalConfig.Common.CertDeploy {
					deletelocalCertificateResource(certData.Domain, certData.Issuer, logger)

				}
				dataCopy[i] = cert
				if config.GlobalConfig.Common.CertDeploy {
					createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
				}
			}
		} else {
			level.Error(logger).Log("msg", fmt.Sprintf("Cannot check certificate renewal because the certificate '%s' is not in config file", certData.Domain)) // #nosec G104
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
				level.Error(logger).Log("msg", "Certificate check renewal failed", "err", err) // #nosec G104
			}
		}
	}
}
