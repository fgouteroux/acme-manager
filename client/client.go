package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/api"
	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/memcache"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/restclient"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"

	"gopkg.in/yaml.v3"
)

var (
	Owner         string
	GlobalConfig  Config
	certificates  []certstore.Certificate
	checkCertLock sync.Mutex

	localCache = memcache.NewLocalCache()
)

type MapDiff struct {
	Create []certstore.Certificate `json:"create"`
	Update []certstore.Certificate `json:"update"`
	Delete []certstore.Certificate `json:"delete"`
}

type CertBackup struct {
	Cert string `json:"cert" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key  string `json:"key" example:"-----BEGIN PRIVATE KEY-----\n..."`
}

func checkCertDiff(old, newCertList []certstore.Certificate, logger log.Logger) (MapDiff, bool) {
	var hasChange bool
	var diff MapDiff

	for _, oldCert := range old {
		idx := slices.IndexFunc(newCertList, func(c certstore.Certificate) bool {
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
		}
	}

	for _, newCert := range newCertList {
		idx := slices.IndexFunc(old, func(c certstore.Certificate) bool {
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

func applyCertFileChanges(acmeClient *restclient.Client, diff MapDiff, logger log.Logger) {
	if GlobalConfig.Common.CmdEnabled {
		err := executeCommand(logger, GlobalConfig.Common, true)
		if err != nil {
			_ = level.Error(logger).Log("msg", "skipping changes because pre_cmd failed", "err", err)
			return
		}
	}

	var hasErrors, hasChange bool
	for _, certData := range diff.Create {
		_ = level.Info(logger).Log("msg", "creating certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
		keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt

		var privateKeyPath string
		if GlobalConfig.Common.CertKeyFileNoGen {
			if !utils.FileExists(keyFilePath) {
				hasErrors = true
				_ = level.Error(logger).Log("err", fmt.Errorf("local private key file '%s' doesn't exists", keyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			privateKeyPath = keyFilePath
		}

		var san []string
		if certData.SAN != "" {
			san = strings.Split(certData.SAN, ",")
		}

		var privateKey []byte
		var err error
		certData.CSR, privateKey, err = utils.GenerateCSRAndPrivateKey(privateKeyPath, certData.KeyType, certData.Domain, san)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			continue
		}

		certDataBytes, _ := json.Marshal(certData)

		var certParams api.CertificateParams
		err = json.Unmarshal(certDataBytes, &certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			continue
		}

		newCert, err := acmeClient.CreateCertificate(certParams, GlobalConfig.Common.CertTimeout)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			continue
		}
		_ = level.Info(logger).Log("msg", "created certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)

		if GlobalConfig.Common.CertBackup {
			data := CertBackup{Cert: newCert.Cert, Key: string(privateKey)}
			vaultSecretPath := fmt.Sprintf("%s/%s/%s/%s", GlobalConfig.Storage.Vault.CertPrefix, newCert.Owner, newCert.Issuer, newCert.Domain)
			err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to backup certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			}
			_ = level.Info(logger).Log("msg", "certificate and private key backed up in vault", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
		}

		if GlobalConfig.Common.CertDeploy {
			hasChange = true
			err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+certData.Issuer, GlobalConfig.Common.CertDirPerm)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			err = createLocalPrivateKeyFile(keyFilePath, privateKey)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local private key file created", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)

			err = createLocalCertificateFile(newCert)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local certificate file created", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		}
	}

	for _, certData := range diff.Update {
		_ = level.Info(logger).Log("msg", "updating certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
		var privateKey []byte
		keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt

		var initCSR string
		if certData.CSR == "" {
			var san []string
			if certData.SAN != "" {
				san = strings.Split(certData.SAN, ",")
			}

			var privateKeyPath string
			if utils.FileExists(keyFilePath) {
				privateKeyPath = keyFilePath
			}

			var err error
			initCSR, privateKey, err = utils.GenerateCSRAndPrivateKey(privateKeyPath, certData.KeyType, certData.Domain, san)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			certData.CSR = initCSR
		}

		certDataBytes, _ := json.Marshal(certData)

		var certParams api.CertificateParams
		err := json.Unmarshal(certDataBytes, &certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			continue
		}

		if GlobalConfig.Common.RevokeOnUpdate {
			certParams.Revoke = true
		}

		newCert, err := acmeClient.UpdateCertificate(certParams, GlobalConfig.Common.CertTimeout)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			continue
		}
		_ = level.Info(logger).Log("msg", "certificate updated", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)

		if GlobalConfig.Common.CertBackup {
			data := CertBackup{Cert: newCert.Cert, Key: string(privateKey)}
			vaultSecretPath := fmt.Sprintf("%s/%s/%s/%s", GlobalConfig.Storage.Vault.CertPrefix, newCert.Owner, newCert.Issuer, newCert.Domain)
			err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to backup certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			}
			_ = level.Info(logger).Log("msg", "certificate and private key backed up in vault", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
		}

		if GlobalConfig.Common.CertDeploy && initCSR == newCert.CSR {
			hasChange = true
			err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+newCert.Issuer, GlobalConfig.Common.CertDirPerm)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			err = createLocalPrivateKeyFile(keyFilePath, privateKey)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local private key file updated", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)

			err = createLocalCertificateFile(newCert)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local certificate file updated", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		}
	}

	for _, certData := range diff.Delete {
		_ = level.Info(logger).Log("msg", "deleting certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
		var cacheKey string
		if GlobalConfig.Common.DelayBeforeDelete != "" {
			duration, _ := time.ParseDuration(GlobalConfig.Common.DelayBeforeDelete)
			cacheKey = certData.Issuer + "/" + certData.Domain
			if cached, found := localCache.Get(cacheKey); found {
				delay := cached.Value.(time.Time)
				now := time.Now()
				if now.Before(delay) {
					delta := delay.Sub(now).String()
					_ = level.Info(logger).Log("msg", fmt.Sprintf("scheduled deletion for %s in %s", cacheKey, delta), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
					continue
				}
			} else {
				delay := time.Now().Add(duration)
				localCache.Set(cacheKey, delay)
				_ = level.Info(logger).Log("msg", fmt.Sprintf("scheduled deletion for %s in %s", cacheKey, GlobalConfig.Common.DelayBeforeDelete), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
		}

		var revoke bool
		if GlobalConfig.Common.RevokeOnDelete {
			revoke = true
		}

		err := acmeClient.DeleteCertificate(certData.Issuer, certData.Domain, revoke, 60)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			continue
		}
		if GlobalConfig.Common.DelayBeforeDelete != "" {
			localCache.Del(cacheKey)
		}
		_ = level.Info(logger).Log("msg", "certificate deleted", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)

		if GlobalConfig.Common.CertDeploy {
			hasChange = true
			keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
			err := deleteLocalPrivateKeyFile(keyFilePath)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local private key file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)

			err = deleteLocalCertificateFile(certData.Issuer, certData.Domain)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local certificate file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			metrics.IncDeletedLocalCertificate(certData.Issuer)
		}
	}

	if !hasErrors && hasChange && GlobalConfig.Common.CmdEnabled {
		err := executeCommand(logger, GlobalConfig.Common, false)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
		}
	}
}

func createLocalCertificateFile(certData certstore.CertMap) error {
	folderPath := GlobalConfig.Common.CertDir + certData.Issuer
	err := utils.CreateNonExistingFolder(folderPath, GlobalConfig.Common.CertDirPerm)
	if err != nil {
		return err
	}
	certFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertFileExt

	certBytes := []byte(certData.Cert)
	err = os.WriteFile(certFilePath, certBytes, GlobalConfig.Common.CertFilePerm)
	if err != nil {
		return fmt.Errorf("unable to save certificate file %s", certFilePath)
	}
	return nil
}

func deleteLocalCertificateFile(issuer, domain string) error {
	certFilePath := GlobalConfig.Common.CertDir + issuer + "/" + domain + GlobalConfig.Common.CertFileExt
	if utils.FileExists(certFilePath) {
		err := os.Remove(certFilePath)
		if err != nil {
			return fmt.Errorf("unable to delete certificate file %s", certFilePath)
		}
	}
	return nil
}

func createLocalPrivateKeyFile(keyFilePath string, privateKey []byte) error {
	err := os.WriteFile(keyFilePath, privateKey, GlobalConfig.Common.CertKeyFilePerm)
	if err != nil {
		return fmt.Errorf("unable to save private key file %s", keyFilePath)
	}
	return nil
}

func deleteLocalPrivateKeyFile(keyFilePath string) error {
	if utils.FileExists(keyFilePath) {
		err := os.Remove(keyFilePath)
		if err != nil {
			return fmt.Errorf("unable to delete private key file %s", keyFilePath)
		}
	}
	return nil
}

func CheckCertificate(logger log.Logger, GlobalConfigPath string, acmeClient *restclient.Client) {
	if !checkCertLock.TryLock() {
		_ = level.Info(logger).Log("msg", "skipping check certificates from config file because another run is in progress")
		return
	}
	defer checkCertLock.Unlock()

	newConfigBytes, err := os.ReadFile(filepath.Clean(GlobalConfigPath))
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to read file %s", GlobalConfigPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}
	var cfg Config
	err = yaml.Unmarshal(newConfigBytes, &cfg)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("ignoring file changes %s because of error", GlobalConfigPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}
	GlobalConfig = cfg
	metrics.SetCertificateConfigError(0)

	_ = level.Info(logger).Log("msg", "check certificates from config file and compare with remote server")

	old, err := acmeClient.GetAllCertificateMetadata(60)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	var newCertList []certstore.Certificate
	var hasChange bool
	var patterns []string

	for _, certData := range GlobalConfig.Certificate {
		patterns = append(patterns, certData.Issuer+"/"+certData.Domain)

		err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+certData.Issuer, GlobalConfig.Common.CertDirPerm)
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			continue
		}

		// Setting default days
		if certData.Days == 0 {
			certData.Days = GlobalConfig.Common.CertDays
		}

		// Setting default key type
		if certData.KeyType == "" {
			certData.KeyType = "ec256"
		}

		idx := slices.IndexFunc(old, func(c certstore.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer
		})

		if idx == -1 {
			newCertList = append(newCertList, certData)
		} else {

			var toUpdate bool
			var toRecreate bool

			var tmp certstore.Certificate

			certFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertFileExt
			certFileExists := utils.FileExists(certFilePath)

			if !certFileExists {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' doesn't exists", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				certificate, err := acmeClient.ReadCertificate(certData, 30)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
					continue
				}
				err = createLocalCertificateFile(certificate)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
					continue
				}
				hasChange = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' restored.", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				metrics.IncCreatedLocalCertificate(certData.Issuer)
			} else {
				var currentCertBytes []byte
				currentCertBytes, err = os.ReadFile(filepath.Clean(certFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
					continue
				}

				var err error
				var certificate certstore.CertMap

				if utils.GenerateFingerprint(currentCertBytes) != old[idx].Fingerprint {

					certificate, err = acmeClient.ReadCertificate(certData, 30)
					if err != nil {
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
						continue
					}

					err = os.WriteFile(certFilePath, []byte(certificate.Cert), GlobalConfig.Common.CertFilePerm)
					if err != nil {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save local certificate file %s", certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
					} else {
						hasChange = true
						_ = level.Info(logger).Log("msg", fmt.Sprintf("deployed local certificate %s", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
						metrics.IncCreatedLocalCertificate(certData.Issuer)
					}
				}
			}

			if certData.KeyType != old[idx].KeyType {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' key_type changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].KeyType,
					certData.KeyType,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)

				keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
				err := deleteLocalPrivateKeyFile(keyFilePath)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				} else {
					_ = level.Info(logger).Log("msg", "local private key file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				}

				err = deleteLocalCertificateFile(certData.Issuer, certData.Domain)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				} else {
					_ = level.Info(logger).Log("msg", "local certificate file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				}
				certData.CSR = ""

			} else {

				certKeyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
				certKeyFileExists := utils.FileExists(certKeyFilePath)

				if !certKeyFileExists && GlobalConfig.Common.CertBackup {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists", certKeyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
					toRecreate, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Domain)
				} else if !certKeyFileExists {
					toRecreate = true
					_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists. Recreation needed.", certKeyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				} else {
					certBytes, err := os.ReadFile(certFilePath)
					if err != nil {
						toRecreate = true
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
						continue
					}

					certKeyBytes, err := os.ReadFile(filepath.Clean(certKeyFilePath))
					if err != nil {
						toRecreate = true
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
						continue
					}

					_, err = tls.X509KeyPair(certBytes, certKeyBytes)
					if err != nil {
						if GlobalConfig.Common.CertBackup {
							_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Restoration needed.", certKeyFilePath, certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
							toRecreate, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Domain)
						} else {
							toRecreate = true
							_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Recreation needed.", certKeyFilePath, certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
						}
					}
				}
			}

			if certData.SAN != old[idx].SAN {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' SAN changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].SAN,
					certData.SAN,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			}
			if certData.Days != old[idx].Days {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' days changed from '%d' to '%d'.",
					certData.Issuer,
					certData.Domain,
					old[idx].Days,
					certData.Days,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			}
			if certData.Bundle != old[idx].Bundle {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' bundle changed from '%v' to '%v'.",
					certData.Issuer,
					certData.Domain,
					old[idx].Bundle,
					certData.Bundle,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			}
			if certData.DNSChallenge != old[idx].DNSChallenge {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' dns_challenge changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].DNSChallenge,
					certData.DNSChallenge,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			}
			if certData.HTTPChallenge != old[idx].HTTPChallenge {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' http_challenge changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].HTTPChallenge,
					certData.HTTPChallenge,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			}
			if certData.RenewalDays != old[idx].RenewalDays {

				if _, _, err := utils.ValidateRenewalDays(certData.RenewalDays); err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
					continue
				}

				toUpdate = true

				if !toRecreate {
					tmp = old[idx]
					tmp.RenewalDays = certData.RenewalDays
				}
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' renewal_days changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].RenewalDays,
					certData.RenewalDays,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			}
			if certData.Labels != old[idx].Labels {
				toUpdate = true

				if !toRecreate {
					tmp = old[idx]
					tmp.Labels = certData.Labels
				}
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' labels changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].Labels,
					certData.Labels,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			}

			if toRecreate {
				newCertList = append(newCertList, certData)
			} else if toUpdate {
				newCertList = append(newCertList, tmp)
			} else {
				newCertList = append(newCertList, old[idx])
			}
		}
	}

	diff, hasChanged := checkCertDiff(old, newCertList, logger)

	if hasChanged {
		applyCertFileChanges(acmeClient, diff, logger)
	} else if hasChange && GlobalConfig.Common.CmdEnabled {
		err := executeCommand(logger, GlobalConfig.Common, false)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
		}
	}
	// delete files that don't match patterns
	_, err = listAndDeleteFiles(logger, patterns)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
	}

	_ = level.Info(logger).Log("msg", "check certificates from config file done")
}

func PullAndCheckCertificateFromRing(logger log.Logger, GlobalConfigPath string, acmeClient *restclient.Client) {
	newConfigBytes, err := os.ReadFile(filepath.Clean(GlobalConfigPath))
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to read file %s", GlobalConfigPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}
	var cfg Config
	err = yaml.Unmarshal(newConfigBytes, &cfg)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("ignoring file changes %s because of error", GlobalConfigPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}
	GlobalConfig = cfg
	metrics.SetCertificateConfigError(0)

	_ = level.Info(logger).Log("msg", "pull and check certificates from remote server")

	allCert, err := acmeClient.GetAllCertificateMetadata(60)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	var hasChange bool
	var patterns []string
	for _, certData := range allCert {

		patterns = append(patterns, certData.Issuer+"/"+certData.Domain)

		err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+certData.Issuer, GlobalConfig.Common.CertDirPerm)
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			continue
		}

		certFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertFileExt
		certFileExists := utils.FileExists(certFilePath)

		if !certFileExists {
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' doesn't exists", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			certificate, err := acmeClient.ReadCertificate(certData, 30)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			err = createLocalCertificateFile(certificate)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}
			hasChange = true
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' restored.", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		} else {
			var currentCertBytes []byte
			currentCertBytes, err = os.ReadFile(filepath.Clean(certFilePath))
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}

			var err error
			var certificate certstore.CertMap

			if utils.GenerateFingerprint(currentCertBytes) != certData.Fingerprint {

				certificate, err = acmeClient.ReadCertificate(certData, 30)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
					continue
				}

				err = os.WriteFile(certFilePath, []byte(certificate.Cert), GlobalConfig.Common.CertFilePerm)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save local certificate file %s", certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				} else {
					hasChange = true
					_ = level.Info(logger).Log("msg", fmt.Sprintf("deployed local certificate %s", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
					metrics.IncCreatedLocalCertificate(certData.Issuer)
				}
			}
		}

		certKeyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
		certKeyFileExists := utils.FileExists(certKeyFilePath)

		if !certKeyFileExists {
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists", certKeyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
			_, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Domain)
		} else {
			certBytes, err := os.ReadFile(filepath.Clean(certFilePath))
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}

			certKeyBytes, err := os.ReadFile(filepath.Clean(certKeyFilePath))
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				continue
			}

			_, err = tls.X509KeyPair(certBytes, certKeyBytes)
			if err != nil {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Restoration needed.", certKeyFilePath, certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "user", Owner)
				_, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Domain)
			}
		}
	}

	if hasChange && GlobalConfig.Common.CmdEnabled {
		err := executeCommand(logger, GlobalConfig.Common, false)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
		}
	}
	// delete files that don't match patterns
	_, err = listAndDeleteFiles(logger, patterns)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
	}
	_ = level.Info(logger).Log("msg", "pull and check certificates done")
}

func executeCommand(logger log.Logger, cfg Common, preCmd bool) error {
	var cmdRun string
	var cmdTimeout int

	if preCmd {
		cmdRun = cfg.PreCmdRun
		cmdTimeout = cfg.PreCmdTimeout
	} else {
		cmdRun = cfg.PostCmdRun
		cmdTimeout = cfg.PostCmdTimeout
	}

	if cmdRun != "" {

		// set default timeout
		if cmdTimeout == 0 {
			cmdTimeout = 60
		}

		cmdArr := strings.Split(cmdRun, " ")
		cmdPath := cmdArr[0]
		cmdArgs := cmdArr[1:]

		run := func(cmdPath string, cmdArgs []string, cmdTimeout int) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cmdTimeout)*time.Second)
			defer cancel()

			var out bytes.Buffer

			cmd := exec.CommandContext(ctx, cmdPath, cmdArgs...)
			cmd.Stdout = &out
			cmd.Stderr = &out

			err := cmd.Run()
			return out.String(), err
		}

		out, err := run(cmdPath, cmdArgs, cmdTimeout)
		if err != nil {
			metrics.IncRunFailedLocalCmd()
			return fmt.Errorf("command '%s %s' failed: %s. Error: %s", cmdPath, strings.Join(cmdArgs, " "), out, err.Error())
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("command '%s %s' successfully executed", cmdPath, strings.Join(cmdArgs, " ")))
		_ = level.Debug(logger).Log("msg", "Command output", "output", out)
		metrics.IncRunSuccessLocalCmd()
	}
	return nil
}

func MapInterfaceToCertBackup(data map[string]interface{}) CertBackup {
	val, _ := json.Marshal(data)
	var result CertBackup
	_ = json.Unmarshal(val, &result)
	return result
}

func getPrivateKeyFromVault(logger log.Logger, certKeyFilePath, certFilePath, issuer, domain string) (bool, bool) {
	secretKeyPath := fmt.Sprintf("%s/%s/%s/%s", GlobalConfig.Storage.Vault.CertPrefix, Owner, issuer, domain)
	secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
	if err != nil {
		_ = level.Error(logger).Log("err", err, "domain", domain, "issuer", issuer, "user", Owner)
		return false, false
	}
	data := MapInterfaceToCertBackup(secret)

	if data.Key != "" {
		certBytes, err := os.ReadFile(filepath.Clean(certFilePath))
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", domain, "issuer", issuer, "user", Owner)
			return true, false
		}

		_, err = tls.X509KeyPair(certBytes, []byte(data.Key))
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Recreation needed.", certKeyFilePath, certFilePath), "err", err, "domain", domain, "issuer", issuer, "user", Owner)
			return true, false
		}
		err = createLocalPrivateKeyFile(certKeyFilePath, []byte(data.Key))
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", domain, "issuer", issuer, "user", Owner)
			return true, false
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' restored.", certKeyFilePath), "domain", domain, "issuer", issuer, "user", Owner)
		return false, true
	}
	_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists. Recreation needed.", certKeyFilePath), "domain", domain, "issuer", issuer, "user", Owner)
	return true, false
}

// listAndDeleteFiles recursively lists directories and deletes files matching the pattern
func listAndDeleteFiles(logger log.Logger, patterns []string) (bool, error) {
	var hasDelete bool
	err := filepath.Walk(GlobalConfig.Common.CertDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			var pattern string
			if strings.HasSuffix(path, GlobalConfig.Common.CertFileExt) {
				pattern = strings.TrimPrefix(strings.TrimSuffix(path, GlobalConfig.Common.CertFileExt), GlobalConfig.Common.CertDir)
			}
			if strings.HasSuffix(path, GlobalConfig.Common.CertKeyFileExt) {
				pattern = strings.TrimPrefix(strings.TrimSuffix(path, GlobalConfig.Common.CertKeyFileExt), GlobalConfig.Common.CertDir)
			}

			if !slices.Contains(patterns, pattern) {
				// Delete the file if it don't match the pattern
				if err := os.Remove(path); err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to delete file '%s'", path), "err", err)
				}
				hasDelete = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf("deleted file '%s'", path))
			}
		}
		return nil
	})
	return hasDelete, err
}
