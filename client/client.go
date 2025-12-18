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

	"github.com/fgouteroux/acme-manager/memcache"
	"github.com/fgouteroux/acme-manager/metrics"
	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/restclient"
	"github.com/fgouteroux/acme-manager/storage/vault"
	"github.com/fgouteroux/acme-manager/utils"

	"gopkg.in/yaml.v3"
)

var (
	Owner         string
	GlobalConfig  Config
	certificates  []models.Certificate
	checkCertLock sync.Mutex

	localCache = memcache.NewLocalCache()
)

type MapDiff struct {
	Create []models.Certificate `json:"create"`
	Update []models.Certificate `json:"update"`
	Delete []models.Certificate `json:"delete"`
}

type CertBackup struct {
	Cert string `json:"cert" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key  string `json:"key" example:"-----BEGIN PRIVATE KEY-----\n..."`
}

func checkCertDiff(old, newCertList []models.Certificate, logger log.Logger) (MapDiff, bool) {
	var hasChange bool
	var diff MapDiff

	for _, oldCert := range old {
		idx := slices.IndexFunc(newCertList, func(c models.Certificate) bool {
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
		idx := slices.IndexFunc(old, func(c models.Certificate) bool {
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
		_ = level.Info(logger).Log("msg", "creating certificate", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
		keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt

		var privateKeyPath string
		if GlobalConfig.Common.CertKeyFileNoGen {
			if !utils.FileExists(keyFilePath) {
				hasErrors = true
				_ = level.Error(logger).Log("err", fmt.Errorf("local private key file '%s' doesn't exists", keyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			privateKeyPath = keyFilePath
		}

		var san []string
		if certData.San != "" {
			san = strings.Split(certData.San, ",")
		}

		var privateKey []byte
		var err error
		certData.Csr, privateKey, err = utils.GenerateCSRAndPrivateKey(privateKeyPath, certData.KeyType, certData.Domain, san)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			continue
		}

		// Save private key BEFORE calling CreateCertificate to prevent loss on timeout
		// If the server times out but continues processing, we still have the key for reconciliation
		if GlobalConfig.Common.CertDeploy {
			err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+certData.Issuer, GlobalConfig.Common.CertDirPerm)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			err = createLocalPrivateKeyFile(keyFilePath, privateKey)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local private key file created", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
		}

		// Backup private key to Vault BEFORE calling CreateCertificate
		if GlobalConfig.Common.CertBackup {
			data := CertBackup{Key: string(privateKey)}
			vaultSecretPath := fmt.Sprintf("%s/%s/%s/%s", GlobalConfig.Storage.Vault.CertPrefix, Owner, certData.Issuer, certData.Domain)
			err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to backup private key to vault", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			} else {
				_ = level.Info(logger).Log("msg", "private key backed up in vault", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			}
		}

		certDataBytes, _ := json.Marshal(certData)

		var certParams models.CertificateParams
		err = json.Unmarshal(certDataBytes, &certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			continue
		}

		newCert, err := acmeClient.CreateCertificate(certParams, GlobalConfig.Common.CertTimeout)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("msg", "failed to create certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			continue
		}
		_ = level.Info(logger).Log("msg", "created certificate", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)

		// Update Vault backup with certificate after successful creation
		if GlobalConfig.Common.CertBackup {
			data := CertBackup{Cert: newCert.Cert, Key: string(privateKey)}
			vaultSecretPath := fmt.Sprintf("%s/%s/%s/%s", GlobalConfig.Storage.Vault.CertPrefix, newCert.Owner, newCert.Issuer, newCert.Domain)
			err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to backup certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			} else {
				_ = level.Info(logger).Log("msg", "certificate and private key backed up in vault", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			}
		}

		if GlobalConfig.Common.CertDeploy {
			hasChange = true
			err = createLocalCertificateFile(newCert)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local certificate file created", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		}
	}

	for _, certData := range diff.Update {
		_ = level.Info(logger).Log("msg", "updating certificate", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
		var privateKey []byte
		keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt

		var initCSR string
		if certData.Csr == "" {
			var san []string
			if certData.San != "" {
				san = strings.Split(certData.San, ",")
			}

			var privateKeyPath string
			if utils.FileExists(keyFilePath) {
				privateKeyPath = keyFilePath
			}

			var err error
			initCSR, privateKey, err = utils.GenerateCSRAndPrivateKey(privateKeyPath, certData.KeyType, certData.Domain, san)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			certData.Csr = initCSR
		}

		certDataBytes, _ := json.Marshal(certData)

		var certParams models.CertificateParams
		err := json.Unmarshal(certDataBytes, &certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			continue
		}

		if GlobalConfig.Common.RevokeOnUpdate {
			certParams.Revoke = true
		}

		newCert, err := acmeClient.UpdateCertificate(certParams, GlobalConfig.Common.CertTimeout)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("msg", "failed to update certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			continue
		}
		_ = level.Info(logger).Log("msg", "certificate updated", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)

		if GlobalConfig.Common.CertBackup {
			data := CertBackup{Cert: newCert.Cert, Key: string(privateKey)}
			vaultSecretPath := fmt.Sprintf("%s/%s/%s/%s", GlobalConfig.Storage.Vault.CertPrefix, newCert.Owner, newCert.Issuer, newCert.Domain)
			err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to backup certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			}
			_ = level.Info(logger).Log("msg", "certificate and private key backed up in vault", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
		}

		if GlobalConfig.Common.CertDeploy && initCSR == newCert.Csr {
			hasChange = true
			err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+newCert.Issuer, GlobalConfig.Common.CertDirPerm)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			err = createLocalPrivateKeyFile(keyFilePath, privateKey)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local private key file updated", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)

			err = createLocalCertificateFile(newCert)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local certificate file updated", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		}
	}

	for _, certData := range diff.Delete {
		_ = level.Info(logger).Log("msg", "deleting certificate", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
		var cacheKey string
		if GlobalConfig.Common.DelayBeforeDelete != "" {
			duration, _ := time.ParseDuration(GlobalConfig.Common.DelayBeforeDelete)
			cacheKey = certData.Issuer + "/" + certData.Domain
			if cached, found := localCache.Get(cacheKey); found {
				delay := cached.Value.(time.Time)
				now := time.Now()
				if now.Before(delay) {
					delta := delay.Sub(now).String()
					_ = level.Info(logger).Log("msg", fmt.Sprintf("scheduled deletion for %s in %s", cacheKey, delta), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
					continue
				}
			} else {
				delay := time.Now().Add(duration)
				localCache.Set(cacheKey, delay)
				_ = level.Info(logger).Log("msg", fmt.Sprintf("scheduled deletion for %s in %s", cacheKey, GlobalConfig.Common.DelayBeforeDelete), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
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
			_ = level.Error(logger).Log("msg", "failed to delete certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			continue
		}
		if GlobalConfig.Common.DelayBeforeDelete != "" {
			localCache.Del(cacheKey)
		}
		_ = level.Info(logger).Log("msg", "certificate deleted", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)

		if GlobalConfig.Common.CertDeploy {
			hasChange = true
			keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
			err := deleteLocalPrivateKeyFile(keyFilePath)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local private key file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)

			err = deleteLocalCertificateFile(certData.Issuer, certData.Domain)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local certificate file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
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

func createLocalCertificateFile(certData models.CertMap) error {
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

	var newCertList []models.Certificate
	var hasChange bool

	for _, certConfig := range GlobalConfig.Certificate {

		certData := certConfig.ToModelsCertificate() // Convert to models.Certificate

		err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+certData.Issuer, GlobalConfig.Common.CertDirPerm)
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			continue
		}

		// Setting default days
		if certData.Days == 0 {
			certData.Days = int32(GlobalConfig.Common.CertDays)
		}

		// Setting default key type
		if certData.KeyType == "" {
			certData.KeyType = "ec256"
		}

		idx := slices.IndexFunc(old, func(c models.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer
		})

		if idx == -1 {
			newCertList = append(newCertList, certData)
		} else {

			var toUpdate bool
			var toRecreate bool

			var tmp models.Certificate

			certFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertFileExt
			certFileExists := utils.FileExists(certFilePath)

			if !certFileExists {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' doesn't exists", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				certificate, err := acmeClient.ReadCertificate(certData, 30)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
					continue
				}
				err = createLocalCertificateFile(certificate)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
					continue
				}
				hasChange = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' restored.", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				metrics.IncCreatedLocalCertificate(certData.Issuer)
			} else {
				var currentCertBytes []byte
				currentCertBytes, err = os.ReadFile(filepath.Clean(certFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
					continue
				}

				var err error
				var certificate models.CertMap

				if utils.GenerateFingerprint(currentCertBytes) != old[idx].Fingerprint {

					certificate, err = acmeClient.ReadCertificate(certData, 30)
					if err != nil {
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
						continue
					}

					err = os.WriteFile(certFilePath, []byte(certificate.Cert), GlobalConfig.Common.CertFilePerm)
					if err != nil {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save local certificate file %s", certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
					} else {
						hasChange = true
						_ = level.Info(logger).Log("msg", fmt.Sprintf("deployed local certificate %s", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)

				keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
				err := deleteLocalPrivateKeyFile(keyFilePath)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				} else {
					_ = level.Info(logger).Log("msg", "local private key file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				}

				err = deleteLocalCertificateFile(certData.Issuer, certData.Domain)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				} else {
					_ = level.Info(logger).Log("msg", "local certificate file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				}
				certData.Csr = ""

			} else {

				certKeyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
				certKeyFileExists := utils.FileExists(certKeyFilePath)

				if !certKeyFileExists && GlobalConfig.Common.CertBackup {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists", certKeyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
					toRecreate, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Domain)
				} else if !certKeyFileExists {
					toRecreate = true
					_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists. Recreation needed.", certKeyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				} else {
					certBytes, err := os.ReadFile(certFilePath)
					if err != nil {
						toRecreate = true
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
						continue
					}

					certKeyBytes, err := os.ReadFile(filepath.Clean(certKeyFilePath))
					if err != nil {
						toRecreate = true
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
						continue
					}

					_, err = tls.X509KeyPair(certBytes, certKeyBytes)
					if err != nil {
						if GlobalConfig.Common.CertBackup {
							_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Restoration needed.", certKeyFilePath, certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
							toRecreate, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Domain)
						} else {
							toRecreate = true
							_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Recreation needed.", certKeyFilePath, certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
						}
					}
				}
			}

			if certData.San != old[idx].San {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' San changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].San,
					certData.San,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			}
			if certData.DnsChallenge != old[idx].DnsChallenge {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' dns_challenge changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].DnsChallenge,
					certData.DnsChallenge,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			}
			if certData.HttpChallenge != old[idx].HttpChallenge {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' http_challenge changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].HttpChallenge,
					certData.HttpChallenge,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			}
			if certData.RenewalDays != old[idx].RenewalDays {

				if _, _, err := utils.ValidateRenewalDays(certData.RenewalDays); err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
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
	for _, certData := range allCert {

		err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+certData.Issuer, GlobalConfig.Common.CertDirPerm)
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			continue
		}

		certFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertFileExt
		certFileExists := utils.FileExists(certFilePath)

		if !certFileExists {
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' doesn't exists", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			certificate, err := acmeClient.ReadCertificate(certData, 30)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			err = createLocalCertificateFile(certificate)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}
			hasChange = true
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' restored.", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		} else {
			var currentCertBytes []byte
			currentCertBytes, err = os.ReadFile(filepath.Clean(certFilePath))
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}

			var err error
			var certificate models.CertMap

			if utils.GenerateFingerprint(currentCertBytes) != certData.Fingerprint {

				certificate, err = acmeClient.ReadCertificate(certData, 30)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
					continue
				}

				err = os.WriteFile(certFilePath, []byte(certificate.Cert), GlobalConfig.Common.CertFilePerm)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save local certificate file %s", certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				} else {
					hasChange = true
					_ = level.Info(logger).Log("msg", fmt.Sprintf("deployed local certificate %s", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
					metrics.IncCreatedLocalCertificate(certData.Issuer)
				}
			}
		}

		certKeyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
		certKeyFileExists := utils.FileExists(certKeyFilePath)

		if !certKeyFileExists {
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists", certKeyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
			_, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Domain)
		} else {
			certBytes, err := os.ReadFile(filepath.Clean(certFilePath))
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}

			certKeyBytes, err := os.ReadFile(filepath.Clean(certKeyFilePath))
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
				continue
			}

			_, err = tls.X509KeyPair(certBytes, certKeyBytes)
			if err != nil {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Restoration needed.", certKeyFilePath, certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "owner", Owner)
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
		_ = level.Error(logger).Log("err", err, "domain", domain, "issuer", issuer, "owner", Owner)
		return false, false
	}
	data := MapInterfaceToCertBackup(secret)

	if data.Key != "" {
		certBytes, err := os.ReadFile(filepath.Clean(certFilePath))
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", domain, "issuer", issuer, "owner", Owner)
			return true, false
		}

		_, err = tls.X509KeyPair(certBytes, []byte(data.Key))
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Recreation needed.", certKeyFilePath, certFilePath), "err", err, "domain", domain, "issuer", issuer, "owner", Owner)
			return true, false
		}
		err = createLocalPrivateKeyFile(certKeyFilePath, []byte(data.Key))
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", domain, "issuer", issuer, "owner", Owner)
			return true, false
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' restored.", certKeyFilePath), "domain", domain, "issuer", issuer, "owner", Owner)
		return false, true
	}
	_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists. Recreation needed.", certKeyFilePath), "domain", domain, "issuer", issuer, "owner", Owner)
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

// CleanupCertificateFiles periodically checks and deletes local certificate files not found on the server
// It also considers certificates in the local config file to avoid deleting keys for pending certificates
func CleanupCertificateFiles(logger log.Logger, interval time.Duration, GlobalConfigPath string, acmeClient *restclient.Client) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		_ = level.Info(logger).Log("msg", "cleanup local certificate files not found on server or config")

		newConfigBytes, err := os.ReadFile(filepath.Clean(GlobalConfigPath))
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to read file %s", GlobalConfigPath), "err", err)
			continue
		}
		var cfg Config
		err = yaml.Unmarshal(newConfigBytes, &cfg)
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("ignoring file changes %s because of error", GlobalConfigPath), "err", err)
			continue
		}

		allCert, err := acmeClient.GetAllCertificateMetadata(60)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}

		// Build patterns from both server certificates and local config
		// This prevents deleting private keys for certificates that are being created
		// (exist in config but not yet on server due to timeout or pending creation)
		patternSet := make(map[string]struct{})

		// Add patterns from server
		for _, certData := range allCert {
			patternSet[certData.Issuer+"/"+certData.Domain] = struct{}{}
		}

		// Add patterns from local config to protect pending certificates
		for _, certConfig := range cfg.Certificate {
			patternSet[certConfig.Issuer+"/"+certConfig.Domain] = struct{}{}
		}

		var patterns []string
		for pattern := range patternSet {
			patterns = append(patterns, pattern)
		}

		hasDelete, err := listAndDeleteFiles(logger, patterns)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}

		if hasDelete && cfg.Common.CmdEnabled {
			err := executeCommand(logger, cfg.Common, false)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
			}
		}

		_ = level.Info(logger).Log("msg", "cleanup done")
	}
}
