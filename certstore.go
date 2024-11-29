package main

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

	"github.com/fgouteroux/acme_manager/account"
	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/cmd"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"
)

var (
	amRingKey  = "collectors/cert"
	certConfig cert.Config
)

type CertStore struct {
	RingConfig ring.AcmeManagerRing
	Logger     log.Logger
	lock       sync.Mutex
}

func (c *CertStore) GetKVRing() ([]cert.Certificate, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	var data []cert.Certificate

	ctx := context.Background()
	cached, err := c.RingConfig.JSONClient.Get(ctx, amRingKey)
	if err != nil {
		level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to get kv store key '%s'", amRingKey), "err", err) // #nosec G104
		return data, err
	}

	if cached != nil {
		content := cached.(*ring.Data).Content
		err = json.Unmarshal([]byte(content), &data)
		if err != nil {
			level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", amRingKey), "err", err) // #nosec G104
			return data, err
		}
	}
	return data, nil
}

func (c *CertStore) PutKVRing(data []cert.Certificate) {
	c.lock.Lock()
	defer c.lock.Unlock()

	level.Info(c.Logger).Log("msg", fmt.Sprintf("Updating kv store key '%s'", amRingKey)) // #nosec G104

	content, _ := json.Marshal(data)
	c.updateKV(string(content))
}

func (c *CertStore) updateKV(content string) {
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
		Key:   amRingKey,
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
		data.Days = *certDays
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

func WatchRingKvStoreChanges(ringConfig ring.AcmeManagerRing, logger log.Logger) {
	ringConfig.KvStore.WatchKey(context.Background(), amRingKey, ring.JSONCodec, func(in interface{}) bool {
		isLeaderNow, _ := ring.IsLeader(ringConfig)
		if !isLeaderNow {
			val := in.(*ring.Data)
			var newCertList []cert.Certificate
			_ = json.Unmarshal([]byte(val.Content), &newCertList)

			old, found := localCache.Get(amRingKey)
			if !found {
				level.Error(logger).Log("msg", "Empty local cache store") // #nosec G104
			} else {
				diff, hasChanged := checkCertDiff(old.Value.([]cert.Certificate), newCertList, logger)

				if hasChanged {
					level.Info(logger).Log("msg", "kv store key changes") // #nosec G104

					if globalConfig.Common.CertDeploy {
						applyRingKvStoreChanges(diff, logger)
					}
					localCache.Set(amRingKey, newCertList)

					if globalConfig.Common.CmdEnabled {
						cmd.Execute(logger, globalConfig)
					}
				} else {
					level.Info(logger).Log("msg", "kv store key no changes") // #nosec G104
				}
			}
		}

		return true // yes, keep watching
	})
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

		if globalConfig.Common.CertDeploy {
			createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
		}
	}

	for _, certData := range diff.Update {
		hasChange = true
		err := deleteRemoteCertificateResource(certData.Domain, certData.Issuer, logger)
		if err != nil {
			return certInfo, err
		}
		if globalConfig.Common.CertDeploy {
			deletelocalCertificateResource(certData.Domain, certData.Issuer, logger)
		}
		newCert, err := createRemoteCertificateResource(certData, logger)
		if err != nil {
			return certInfo, err
		}
		certInfo = append(certInfo, newCert)
		if globalConfig.Common.CertDeploy {
			createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
		}
	}

	for _, certData := range diff.Delete {
		hasChange = true
		err := deleteRemoteCertificateResource(certData.Domain, certData.Issuer, logger)
		if err != nil {
			return certInfo, err
		}
		if globalConfig.Common.CertDeploy {
			deletelocalCertificateResource(certData.Domain, certData.Issuer, logger)
		}
	}

	if hasChange && globalConfig.Common.CmdEnabled {
		cmd.Execute(logger, globalConfig)
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
	err := utils.CreateNonExistingFolder(globalConfig.Common.CertDir + issuer)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		return
	}
	certFilePath := globalConfig.Common.CertDir + issuer + "/" + certName + ".crt"
	keyFilePath := globalConfig.Common.CertDir + issuer + "/" + certName + ".key"

	secretKeyPath := globalConfig.Storage.Vault.SecretPrefix + "/" + issuer + "/" + certName
	secret, err := vault.GetSecretWithAppRole(vaultClient, globalConfig.Storage.Vault, secretKeyPath)
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
	certFilePath := globalConfig.Common.CertDir + issuer + "/" + certName + ".crt"
	keyFilePath := globalConfig.Common.CertDir + issuer + "/" + certName + ".key"

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
	vaultSecretPath := fmt.Sprintf("%s/%s/%s", globalConfig.Storage.Vault.SecretPrefix, certData.Issuer, certData.Domain)
	domain := utils.SanitizedDomain(logger, certData.Domain)

	baseCertificateFilePath := fmt.Sprintf("%s/%s/%s/", globalConfig.Common.RootPathCertificate, certData.Issuer, domain)
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
			request.NotAfter = time.Now().Add(time.Duration(*certDays) * 24 * time.Hour)
		}
	}

	resource, err := account.AcmeClient[certData.Issuer].Certificate.Obtain(request)
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
	err = vault.PutSecretWithAppRole(vaultClient, globalConfig.Storage.Vault, vaultSecretPath, data)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		return newCert, err
	}
	// remove local cert once stored in vault
	err = os.RemoveAll(baseCertificateFilePath)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		return newCert, err
	}

	newCert, err = kvStore(certData, resource.Certificate, resource.PrivateKey)
	if err != nil {
		return newCert, err
	}

	return newCert, nil
}

func deleteRemoteCertificateResource(name, issuer string, logger log.Logger) error {
	vaultSecretPath := fmt.Sprintf("%s/%s/%s", globalConfig.Storage.Vault.SecretPrefix, issuer, name)
	domain := utils.SanitizedDomain(logger, name)
	data, err := vault.GetSecretWithAppRole(vaultClient, globalConfig.Storage.Vault, vaultSecretPath)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		return err
	}

	if cert64, ok := data["cert"]; ok {
		certBytes, _ := base64.StdEncoding.DecodeString(cert64.(string))
		err = account.AcmeClient[issuer].Certificate.Revoke(certBytes)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return err
		}

		level.Info(logger).Log("msg", fmt.Sprintf("Certificate domain %s for %s issuer revoked", domain, issuer)) // #nosec G104
		err = vault.DeleteSecretWithAppRole(vaultClient, globalConfig.Storage.Vault, vaultSecretPath)
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
	if !globalConfig.Common.CertDeploy {
		return nil
	}

	data, err := amStore.GetKVRing()
	if err != nil {
		return err
	}

	var hasChange bool
	for _, certData := range data {
		certFilePath := globalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
		keyFilePath := globalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

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
				err := utils.CreateNonExistingFolder(globalConfig.Common.CertDir + certData.Issuer)
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
				err := utils.CreateNonExistingFolder(globalConfig.Common.CertDir + certData.Issuer)
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
					continue
				}
			}

			var secret map[string]interface{}
			if utils.GenerateFingerprint(certBytes) != certData.Fingerprint {
				hasChange = true
				secretKeyPath := globalConfig.Storage.Vault.SecretPrefix + "/" + certData.Issuer + "/" + certData.Domain
				secret, err = vault.GetSecretWithAppRole(vaultClient, globalConfig.Storage.Vault, secretKeyPath)
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
				secretKeyPath := globalConfig.Storage.Vault.SecretPrefix + "/" + certData.Issuer + "/" + certData.Domain
				if secret == nil {
					secret, err = vault.GetSecretWithAppRole(vaultClient, globalConfig.Storage.Vault, secretKeyPath)
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
	if hasChange && globalConfig.Common.CmdEnabled {
		cmd.Execute(logger, globalConfig)
	}
	return nil
}

func WatchLocalCertificate(amStore *CertStore, logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		err := CheckAndDeployLocalCertificate(amStore, logger)
		if err != nil {
			level.Error(logger).Log("msg", "Check local certificate failed", "err", err) // #nosec G104
		}
	}
}

func CheckCertExpiration(amStore *CertStore, logger log.Logger) error {
	data, err := amStore.GetKVRing()
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
				c.RenewalDays = *certDaysRenewal
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
				if globalConfig.Common.CertDeploy {
					deletelocalCertificateResource(certData.Domain, certData.Issuer, logger)

				}
				dataCopy[i] = cert
				if globalConfig.Common.CertDeploy {
					createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
				}
			}
		} else {
			level.Error(logger).Log("msg", fmt.Sprintf("Cannot check certificate renewal because the certificate '%s' is not in config file", certData.Domain)) // #nosec G104
		}
	}
	if hasChange {
		localCache.Set(amRingKey, dataCopy)
		amStore.PutKVRing(dataCopy)

		if globalConfig.Common.CmdEnabled {
			cmd.Execute(logger, globalConfig)
		}

	}
	return nil
}

func WatchCertExpiration(amStore *CertStore, logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(amStore.RingConfig)
		if isLeaderNow {
			err := CheckCertExpiration(amStore, logger)
			if err != nil {
				level.Error(logger).Log("msg", "Certificate check renewal failed", "err", err) // #nosec G104
			}
		}
	}
}
