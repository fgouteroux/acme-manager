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
	pullCertLock  sync.Mutex
	cleanupLock   sync.Mutex

	localCache = memcache.NewLocalCache()
)

type MapDiff struct {
	Create []models.Certificate `json:"create"`
	Update []models.Certificate `json:"update"`
	Delete []models.Certificate `json:"delete"`
}

type CertBackup struct {
	Cert     string `json:"cert" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key      string `json:"key" example:"-----BEGIN PRIVATE KEY-----\n..."`
	CAIssuer string `json:"ca_issuer,omitempty" example:"-----BEGIN CERTIFICATE-----\n..."`
}

// certIdentityMatch returns true when two certificates represent the same logical entry.
// Named certs (name != "") are identified by name alone — issuer and domain are mutable.
// Unnamed certs keep the legacy domain+issuer identity.
func certIdentityMatch(a, b models.Certificate) bool {
	if a.Name != "" || b.Name != "" {
		return a.Name == b.Name
	}
	return a.Domain == b.Domain && a.Issuer == b.Issuer
}

func checkCertDiff(old, newCertList []models.Certificate, logger log.Logger) (MapDiff, bool) {
	var hasChange bool
	var diff MapDiff

	for _, oldCert := range old {
		idx := slices.IndexFunc(newCertList, func(c models.Certificate) bool {
			return certIdentityMatch(c, oldCert)
		})

		// key to delete
		if idx == -1 {
			hasChange = true
			diff.Delete = append(diff.Delete, oldCert)
		} else if idx >= 0 && oldCert != newCertList[idx] {
			hasChange = true
			diff.Update = append(diff.Update, newCertList[idx])
		}
	}

	for _, newCert := range newCertList {
		idx := slices.IndexFunc(old, func(c models.Certificate) bool {
			return certIdentityMatch(c, newCert)
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
		_ = level.Info(logger).Log("msg", "creating certificate", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
		keyFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertKeyFileExt)

		var privateKeyPath string
		if GlobalConfig.Common.CertKeyFileNoGen {
			if !utils.FileExists(keyFilePath) {
				hasErrors = true
				_ = level.Error(logger).Log("err", fmt.Errorf("local private key file '%s' doesn't exists", keyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			continue
		}

		certDataBytes, _ := json.Marshal(certData)

		var certParams models.CertificateParams
		err = json.Unmarshal(certDataBytes, &certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			continue
		}

		newCert, err := acmeClient.CreateCertificate(certParams, GlobalConfig.Common.CertTimeout)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("msg", "failed to create certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			continue
		}
		_ = level.Info(logger).Log("msg", "created certificate", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)

		// Update Vault backup with certificate after successful creation
		if GlobalConfig.Common.CertBackup {
			data := CertBackup{Cert: newCert.Cert, Key: string(privateKey), CAIssuer: newCert.CAIssuer}
			vaultSecretPath := certVaultPath(GlobalConfig.Storage.Vault.CertPrefix, newCert.Owner, newCert.Issuer, newCert.Name, newCert.Domain)
			err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to backup certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			}
			_ = level.Info(logger).Log("msg", "certificate and private key backed up in vault", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
		}

		if GlobalConfig.Common.CertDeploy {
			hasChange = true
			err := utils.CreateNonExistingFolder(certLocalDir(GlobalConfig.Common.CertDir, newCert.Issuer, newCert.Name), GlobalConfig.Common.CertDirPerm)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			err = createLocalPrivateKeyFile(keyFilePath, privateKey)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local private key file created", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)

			err = createLocalCertificateFile(newCert)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local certificate file created", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		}
	}

	for _, certData := range diff.Update {
		_ = level.Info(logger).Log("msg", "updating certificate", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
		var privateKey []byte
		keyFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertKeyFileExt)

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
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			certData.Csr = initCSR
		}

		certDataBytes, _ := json.Marshal(certData)

		var certParams models.CertificateParams
		err := json.Unmarshal(certDataBytes, &certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			continue
		}

		if GlobalConfig.Common.RevokeOnUpdate {
			certParams.Revoke = true
		}

		newCert, err := acmeClient.UpdateCertificate(certParams, GlobalConfig.Common.CertTimeout)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("msg", "failed to update certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			continue
		}
		_ = level.Info(logger).Log("msg", "certificate updated", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)

		if GlobalConfig.Common.CertBackup {
			data := CertBackup{Cert: newCert.Cert, Key: string(privateKey), CAIssuer: newCert.CAIssuer}
			vaultSecretPath := certVaultPath(GlobalConfig.Storage.Vault.CertPrefix, newCert.Owner, newCert.Issuer, newCert.Name, newCert.Domain)
			err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to backup certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			}
			_ = level.Info(logger).Log("msg", "certificate and private key backed up in vault", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
		}

		if GlobalConfig.Common.CertDeploy && initCSR == newCert.Csr {
			hasChange = true
			err := utils.CreateNonExistingFolder(certLocalDir(GlobalConfig.Common.CertDir, newCert.Issuer, newCert.Name), GlobalConfig.Common.CertDirPerm)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			err = createLocalPrivateKeyFile(keyFilePath, privateKey)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local private key file updated", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)

			err = createLocalCertificateFile(newCert)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local certificate file updated", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		}
	}

	for _, certData := range diff.Delete {
		_ = level.Info(logger).Log("msg", "deleting certificate", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
		var cacheKey string
		if GlobalConfig.Common.DelayBeforeDelete != "" {
			duration, _ := time.ParseDuration(GlobalConfig.Common.DelayBeforeDelete)
			cacheKey = certData.Issuer + "/" + certData.Name + "/" + certData.Domain
			if cached, found := localCache.Get(cacheKey); found {
				delay := cached.Value.(time.Time)
				now := time.Now()
				if now.Before(delay) {
					delta := delay.Sub(now).String()
					_ = level.Info(logger).Log("msg", fmt.Sprintf("scheduled deletion for %s in %s", cacheKey, delta), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					continue
				}
			} else {
				delay := time.Now().Add(duration)
				localCache.Set(cacheKey, delay)
				_ = level.Info(logger).Log("msg", fmt.Sprintf("scheduled deletion for %s in %s", cacheKey, GlobalConfig.Common.DelayBeforeDelete), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
		}

		var revoke bool
		if GlobalConfig.Common.RevokeOnDelete {
			revoke = true
		}

		err := acmeClient.DeleteCertificate(certData.Issuer, certData.Domain, certData.Name, revoke, 60)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("msg", "failed to delete certificate", "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			continue
		}
		if GlobalConfig.Common.DelayBeforeDelete != "" {
			localCache.Del(cacheKey)
		}
		_ = level.Info(logger).Log("msg", "certificate deleted", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)

		if GlobalConfig.Common.CertDeploy {
			hasChange = true
			keyFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertKeyFileExt)
			err := deleteLocalPrivateKeyFile(keyFilePath)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local private key file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)

			err = deleteLocalCertificateFile(certData.Issuer, certData.Name, certData.Domain)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			_ = level.Info(logger).Log("msg", "local certificate file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
	folderPath := certLocalDir(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name)
	err := utils.CreateNonExistingFolder(folderPath, GlobalConfig.Common.CertDirPerm)
	if err != nil {
		return err
	}
	certFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertFileExt)

	certBytes := []byte(certData.Cert)
	err = os.WriteFile(certFilePath, certBytes, GlobalConfig.Common.CertFilePerm)
	if err != nil {
		return fmt.Errorf("unable to save certificate file %s", certFilePath)
	}

	// Write CA chain file only when bundle=false and CAIssuer is available
	if !certData.Bundle && certData.CAIssuer != "" {
		caFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertCAFileExt)
		err = os.WriteFile(caFilePath, []byte(certData.CAIssuer), GlobalConfig.Common.CertFilePerm)
		if err != nil {
			return fmt.Errorf("unable to save CA chain file %s", caFilePath)
		}
	}

	return nil
}

func deleteLocalCertificateFile(issuer, name, domain string) error {
	certFilePath := certLocalPath(GlobalConfig.Common.CertDir, issuer, name, domain, GlobalConfig.Common.CertFileExt)
	if utils.FileExists(certFilePath) {
		err := os.Remove(certFilePath)
		if err != nil {
			return fmt.Errorf("unable to delete certificate file %s", certFilePath)
		}
	}

	// Also delete CA chain file if it exists
	caFilePath := certLocalPath(GlobalConfig.Common.CertDir, issuer, name, domain, GlobalConfig.Common.CertCAFileExt)
	if utils.FileExists(caFilePath) {
		err := os.Remove(caFilePath)
		if err != nil {
			return fmt.Errorf("unable to delete CA chain file %s", caFilePath)
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
		_ = level.Debug(logger).Log("msg", "skipping check certificates from config file because another run is in progress")
		return
	}
	defer checkCertLock.Unlock()
	if !cleanupLock.TryLock() {
		_ = level.Debug(logger).Log("msg", "skipping check certificates from config file because cleanup is in progress")
		return
	}
	defer cleanupLock.Unlock()

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
	if err := cfg.ValidateConfigPath(GlobalConfigPath); err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("ignoring file changes %s because of error", GlobalConfigPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}
	GlobalConfig = cfg
	metrics.SetCertificateConfigError(0)

	_ = level.Debug(logger).Log("msg", "check certificates from config file and compare with remote server")

	old, err := acmeClient.GetAllCertificateMetadata(60)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	var newCertList []models.Certificate
	var hasChange bool

	for _, certConfig := range GlobalConfig.Certificate {

		certData := certConfig.ToModelsCertificate() // Convert to models.Certificate

		err := utils.CreateNonExistingFolder(certLocalDir(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name), GlobalConfig.Common.CertDirPerm)
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
			return certIdentityMatch(c, certData)
		})

		if idx == -1 {
			newCertList = append(newCertList, certData)
		} else {

			var toUpdate bool
			var toRecreate bool

			var tmp models.Certificate

			// For named certs, issuer or domain may have changed; skip local-file checks in that
			// case — the new path doesn't exist yet and will be written by the update flow.
			domainChanged := certData.Name != "" && (certData.Domain != old[idx].Domain || certData.Issuer != old[idx].Issuer)
			if domainChanged {
				toRecreate = true
				if certData.Issuer != old[idx].Issuer {
					_ = level.Info(logger).Log("msg", fmt.Sprintf(
						"certificate name '%s' issuer changed from '%s' to '%s'.",
						certData.Name, old[idx].Issuer, certData.Issuer,
					), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				}
				if certData.Domain != old[idx].Domain {
					_ = level.Info(logger).Log("msg", fmt.Sprintf(
						"certificate name '%s' domain changed from '%s' to '%s'.",
						certData.Name, old[idx].Domain, certData.Domain,
					), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				}
			}

			certFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertFileExt)

			// Skip all local-file checks when domain changed — files at the new path don't
			// exist yet and will be written by the update flow.
			if !domainChanged {
				certFileExists := utils.FileExists(certFilePath)

				if !certFileExists {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' doesn't exists", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					certificate, err := acmeClient.ReadCertificate(certData, 30)
					if err != nil {
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
						continue
					}
					err = createLocalCertificateFile(certificate)
					if err != nil {
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
						continue
					}
					hasChange = true
					_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' restored.", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					metrics.IncCreatedLocalCertificate(certData.Issuer)
				} else {
					var currentCertBytes []byte
					currentCertBytes, err = os.ReadFile(filepath.Clean(certFilePath))
					if err != nil {
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
						continue
					}

					var err error
					var certificate models.CertMap

					if utils.GenerateFingerprint(currentCertBytes) != old[idx].Fingerprint {

						certificate, err = acmeClient.ReadCertificate(certData, 30)
						if err != nil {
							_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
							continue
						}

						err = os.WriteFile(certFilePath, []byte(certificate.Cert), GlobalConfig.Common.CertFilePerm)
						if err != nil {
							_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save local certificate file %s", certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
						} else {
							hasChange = true
							_ = level.Info(logger).Log("msg", fmt.Sprintf("deployed local certificate %s", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
							metrics.IncCreatedLocalCertificate(certData.Issuer)
						}

						// Also restore CA chain file when bundle=false
						if !certData.Bundle && certificate.CAIssuer != "" {
							caFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertCAFileExt)
							err = os.WriteFile(caFilePath, []byte(certificate.CAIssuer), GlobalConfig.Common.CertFilePerm)
							if err != nil {
								_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save CA chain file %s", caFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
							} else {
								_ = level.Info(logger).Log("msg", fmt.Sprintf("restored CA chain file %s", caFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
							}
						}
					}
				}
			}

			// Check and restore CA chain file if bundle=false.
			// Skip when domain changed — the new path doesn't exist yet; the update flow will create it.
			if !certData.Bundle && !domainChanged {
				caFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertCAFileExt)
				caFileExists := utils.FileExists(caFilePath)

				if !caFileExists {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("local CA chain file '%s' doesn't exist", caFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					certificate, err := acmeClient.ReadCertificate(certData, 30)
					if err != nil {
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					} else if certificate.CAIssuer != "" {
						err = os.WriteFile(caFilePath, []byte(certificate.CAIssuer), GlobalConfig.Common.CertFilePerm)
						if err != nil {
							_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save CA chain file %s", caFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
						} else {
							hasChange = true
							_ = level.Info(logger).Log("msg", fmt.Sprintf("restored CA chain file %s", caFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
						}
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
					"domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)

				keyFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertKeyFileExt)
				err := deleteLocalPrivateKeyFile(keyFilePath)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				} else {
					_ = level.Info(logger).Log("msg", "local private key file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				}

				err = deleteLocalCertificateFile(certData.Issuer, certData.Name, certData.Domain)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				} else {
					_ = level.Info(logger).Log("msg", "local certificate file deleted", "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				}
				certData.Csr = ""

			} else if !domainChanged {
				// Skip key file check when domain changed — files at the new path don't exist yet
				// and will be created by the update flow.
				certKeyFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertKeyFileExt)
				certKeyFileExists := utils.FileExists(certKeyFilePath)

				if !certKeyFileExists && GlobalConfig.Common.CertBackup {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists", certKeyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					toRecreate, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Name, certData.Domain)
				} else if !certKeyFileExists {
					toRecreate = true
					_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists. Recreation needed.", certKeyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				} else {
					certBytes, err := os.ReadFile(certFilePath)
					if err != nil {
						toRecreate = true
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
						continue
					}

					certKeyBytes, err := os.ReadFile(filepath.Clean(certKeyFilePath))
					if err != nil {
						toRecreate = true
						_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
						continue
					}

					_, err = tls.X509KeyPair(certBytes, certKeyBytes)
					if err != nil {
						if GlobalConfig.Common.CertBackup {
							_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Restoration needed.", certKeyFilePath, certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
							toRecreate, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Name, certData.Domain)
						} else {
							toRecreate = true
							_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Recreation needed.", certKeyFilePath, certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			}
			if certData.Profile != old[idx].Profile {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"certificate issuer '%s' for domain '%s' profile changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].Profile,
					certData.Profile,
				),
					"domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			}
			if certData.RenewalDays != old[idx].RenewalDays {

				if _, _, err := utils.ValidateRenewalDays(certData.RenewalDays); err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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
					"domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
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

	_ = level.Debug(logger).Log("msg", "check certificates from config file done")
}

func PullAndCheckCertificateFromRing(logger log.Logger, GlobalConfigPath string, acmeClient *restclient.Client) {
	if !pullCertLock.TryLock() {
		_ = level.Debug(logger).Log("msg", "skipping pull certificates from ring because another run is in progress")
		return
	}
	defer pullCertLock.Unlock()
	if !cleanupLock.TryLock() {
		_ = level.Debug(logger).Log("msg", "skipping pull certificates from ring because cleanup is in progress")
		return
	}
	defer cleanupLock.Unlock()

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
	if err := cfg.ValidateConfigPath(GlobalConfigPath); err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("ignoring file changes %s because of error", GlobalConfigPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}
	GlobalConfig = cfg
	metrics.SetCertificateConfigError(0)

	_ = level.Debug(logger).Log("msg", "pull and check certificates from remote server")

	allCert, err := acmeClient.GetAllCertificateMetadata(60)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	var hasChange bool
	for _, certData := range allCert {

		err := utils.CreateNonExistingFolder(certLocalDir(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name), GlobalConfig.Common.CertDirPerm)
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			continue
		}

		certFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertFileExt)
		certFileExists := utils.FileExists(certFilePath)

		if !certFileExists {
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' doesn't exists", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			certificate, err := acmeClient.ReadCertificate(certData, 30)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			err = createLocalCertificateFile(certificate)
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}
			hasChange = true
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file '%s' restored.", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		} else {
			var currentCertBytes []byte
			currentCertBytes, err = os.ReadFile(filepath.Clean(certFilePath))
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}

			var err error
			var certificate models.CertMap

			if utils.GenerateFingerprint(currentCertBytes) != certData.Fingerprint {

				certificate, err = acmeClient.ReadCertificate(certData, 30)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					continue
				}

				err = os.WriteFile(certFilePath, []byte(certificate.Cert), GlobalConfig.Common.CertFilePerm)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save local certificate file %s", certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				} else {
					hasChange = true
					_ = level.Info(logger).Log("msg", fmt.Sprintf("deployed local certificate %s", certFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					metrics.IncCreatedLocalCertificate(certData.Issuer)
				}

				// Also restore CA chain file when bundle=false
				if !certData.Bundle && certificate.CAIssuer != "" {
					caFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertCAFileExt)
					err = os.WriteFile(caFilePath, []byte(certificate.CAIssuer), GlobalConfig.Common.CertFilePerm)
					if err != nil {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save CA chain file %s", caFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					} else {
						_ = level.Info(logger).Log("msg", fmt.Sprintf("restored CA chain file %s", caFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					}
				}
			}
		}

		// Check and restore CA chain file if bundle=false
		if !certData.Bundle {
			caFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertCAFileExt)
			caFileExists := utils.FileExists(caFilePath)

			if !caFileExists {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("local CA chain file '%s' doesn't exist", caFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				certificate, err := acmeClient.ReadCertificate(certData, 30)
				if err != nil {
					_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				} else if certificate.CAIssuer != "" {
					err = os.WriteFile(caFilePath, []byte(certificate.CAIssuer), GlobalConfig.Common.CertFilePerm)
					if err != nil {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to save CA chain file %s", caFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					} else {
						hasChange = true
						_ = level.Info(logger).Log("msg", fmt.Sprintf("restored CA chain file %s", caFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
					}
				}
			}
		}

		certKeyFilePath := certLocalPath(GlobalConfig.Common.CertDir, certData.Issuer, certData.Name, certData.Domain, GlobalConfig.Common.CertKeyFileExt)
		certKeyFileExists := utils.FileExists(certKeyFilePath)

		if !certKeyFileExists {
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists", certKeyFilePath), "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
			_, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Name, certData.Domain)
		} else {
			certBytes, err := os.ReadFile(filepath.Clean(certFilePath))
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}

			certKeyBytes, err := os.ReadFile(filepath.Clean(certKeyFilePath))
			if err != nil {
				_ = level.Error(logger).Log("err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				continue
			}

			_, err = tls.X509KeyPair(certBytes, certKeyBytes)
			if err != nil {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Restoration needed.", certKeyFilePath, certFilePath), "err", err, "domain", certData.Domain, "issuer", certData.Issuer, "name", certData.Name, "owner", Owner)
				_, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Name, certData.Domain)
			}
		}
	}

	if hasChange && GlobalConfig.Common.CmdEnabled {
		err := executeCommand(logger, GlobalConfig.Common, false)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
		}
	}
	_ = level.Debug(logger).Log("msg", "pull and check certificates done")
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
			metrics.IncRunFailedLocalCmd(cmdPath)
			return fmt.Errorf("command '%s %s' failed: %s. Error: %s", cmdPath, strings.Join(cmdArgs, " "), out, err.Error())
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("command '%s %s' successfully executed", cmdPath, strings.Join(cmdArgs, " ")))
		_ = level.Debug(logger).Log("msg", "Command output", "output", out)
		metrics.IncRunSuccessLocalCmd(cmdPath)
	}
	return nil
}

func MapInterfaceToCertBackup(data map[string]interface{}) CertBackup {
	val, _ := json.Marshal(data)
	var result CertBackup
	_ = json.Unmarshal(val, &result)
	return result
}

// certVaultPath returns the Vault KV path for a certificate.
// When name is empty the legacy 4-segment path is used (backward compatible).
func certVaultPath(prefix, owner, issuer, name, domain string) string {
	if name != "" {
		return fmt.Sprintf("%s/%s/%s/%s/%s", prefix, owner, issuer, name, domain)
	}
	return fmt.Sprintf("%s/%s/%s/%s", prefix, owner, issuer, domain)
}

// certLocalDir returns the local directory for a certificate.
// When name is non-empty a subdirectory is added to avoid filename collisions.
func certLocalDir(certDir, issuer, name string) string {
	if name != "" {
		return certDir
	}
	return certDir + issuer
}

// certLocalPath returns the full local file path for a certificate file.
func certLocalPath(certDir, issuer, name, domain, ext string) string {
	if name != "" {
		return certDir + name + ext
	}
	return certLocalDir(certDir, issuer, name) + "/" + domain + ext
}

func getPrivateKeyFromVault(logger log.Logger, certKeyFilePath, certFilePath, issuer, name, domain string) (bool, bool) {
	secretKeyPath := certVaultPath(GlobalConfig.Storage.Vault.CertPrefix, Owner, issuer, name, domain)
	secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
	if err != nil {
		_ = level.Error(logger).Log("err", err, "domain", domain, "issuer", issuer, "name", name, "owner", Owner)
		return false, false
	}
	data := MapInterfaceToCertBackup(secret)

	if data.Key != "" {
		certBytes, err := os.ReadFile(filepath.Clean(certFilePath))
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", domain, "issuer", issuer, "name", name, "owner", Owner)
			return true, false
		}

		_, err = tls.X509KeyPair(certBytes, []byte(data.Key))
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("local private key file '%s' and certificate file '%s' error. Recreation needed.", certKeyFilePath, certFilePath), "err", err, "domain", domain, "issuer", issuer, "name", name, "owner", Owner)
			return true, false
		}
		err = createLocalPrivateKeyFile(certKeyFilePath, []byte(data.Key))
		if err != nil {
			_ = level.Error(logger).Log("err", err, "domain", domain, "issuer", issuer, "name", name, "owner", Owner)
			return true, false
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' restored.", certKeyFilePath), "domain", domain, "issuer", issuer, "name", name, "owner", Owner)
		return false, true
	}
	_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file '%s' doesn't exists. Recreation needed.", certKeyFilePath), "domain", domain, "issuer", issuer, "name", name, "owner", Owner)
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
			if strings.HasSuffix(path, GlobalConfig.Common.CertCAFileExt) {
				pattern = strings.TrimPrefix(strings.TrimSuffix(path, GlobalConfig.Common.CertCAFileExt), GlobalConfig.Common.CertDir)
			} else if strings.HasSuffix(path, GlobalConfig.Common.CertFileExt) {
				pattern = strings.TrimPrefix(strings.TrimSuffix(path, GlobalConfig.Common.CertFileExt), GlobalConfig.Common.CertDir)
			} else if strings.HasSuffix(path, GlobalConfig.Common.CertKeyFileExt) {
				pattern = strings.TrimPrefix(strings.TrimSuffix(path, GlobalConfig.Common.CertKeyFileExt), GlobalConfig.Common.CertDir)
			}

			if pattern != "" && !slices.Contains(patterns, pattern) {
				// Delete the file if it don't match the pattern
				if err := os.Remove(path); err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("cleanup: failed to delete file '%s'", path), "err", err)
				}
				hasDelete = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf("cleanup: file '%s' deleted", path))
			}
		}
		return nil
	})
	return hasDelete, err
}

func runCleanup(logger log.Logger, GlobalConfigPath string, acmeClient *restclient.Client) {
	_ = level.Debug(logger).Log("msg", "cleanup local certificate files not found on server or config")

	newConfigBytes, err := os.ReadFile(filepath.Clean(GlobalConfigPath))
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to read file %s", GlobalConfigPath), "err", err)
		return
	}
	var cfg Config
	if err = yaml.Unmarshal(newConfigBytes, &cfg); err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("ignoring file changes %s because of error", GlobalConfigPath), "err", err)
		return
	}
	if err = cfg.ValidateConfigPath(GlobalConfigPath); err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("ignoring file changes %s because of error", GlobalConfigPath), "err", err)
		return
	}

	allCert, err := acmeClient.GetAllCertificateMetadata(60)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	// Build patterns from both server certificates and local config.
	// Local config protects private keys for certs pending creation (not yet on server).
	patternSet := make(map[string]struct{})
	for _, certData := range allCert {
		if certData.Name != "" {
			patternSet[certData.Name] = struct{}{}
		} else {
			patternSet[certData.Issuer+"/"+certData.Domain] = struct{}{}
		}
	}
	for _, certConfig := range cfg.Certificate {
		if certConfig.Name != "" {
			patternSet[certConfig.Name] = struct{}{}
		} else {
			patternSet[certConfig.Issuer+"/"+certConfig.Domain] = struct{}{}
		}
	}

	var patterns []string
	for pattern := range patternSet {
		patterns = append(patterns, pattern)
	}

	hasDelete, err := listAndDeleteFiles(logger, patterns)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	if hasDelete && cfg.Common.CmdEnabled {
		if err := executeCommand(logger, cfg.Common, false); err != nil {
			_ = level.Error(logger).Log("err", err)
		}
	}

	_ = level.Debug(logger).Log("msg", "cleanup done")
}

// CleanupCertificateFiles periodically checks and deletes local certificate files not found on the server
// It also considers certificates in the local config file to avoid deleting keys for pending certificates
func CleanupCertificateFiles(logger log.Logger, interval time.Duration, GlobalConfigPath string, acmeClient *restclient.Client) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if !cleanupLock.TryLock() {
			_ = level.Debug(logger).Log("msg", "skipping cleanup because a certificate run is in progress")
			continue
		}
		runCleanup(logger, GlobalConfigPath, acmeClient)
		cleanupLock.Unlock()
	}
}
