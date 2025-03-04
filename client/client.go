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
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/api"
	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/restclient"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"

	"gopkg.in/yaml.v3"
)

var (
	Owner        string
	GlobalConfig Config
	certificates []certstore.Certificate
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
			_ = level.Error(logger).Log("msg", "Skipping changes because pre_cmd failed", "err", err)
			return
		}
	}

	var hasErrors, hasChange bool
	for _, certData := range diff.Create {
		keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt

		var privateKeyPath string
		if GlobalConfig.Common.CertKeyFileNoGen {
			if !utils.FileExists(keyFilePath) {
				hasErrors = true
				_ = level.Error(logger).Log("err", fmt.Errorf("local private key file '%s' doesn't exists", keyFilePath))
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
		certData.CSR, privateKey, err = utils.GenerateCSRAndPrivateKey(privateKeyPath, certData.Domain, san)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err)
			continue
		}

		certDataBytes, _ := json.Marshal(certData)

		var certParams api.CertificateParams
		err = json.Unmarshal(certDataBytes, &certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err)
			continue
		}

		newCert, err := acmeClient.CreateCertificate(certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err)
			continue
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' created", newCert.Domain))

		if GlobalConfig.Common.CertBackup {
			data := CertBackup{Cert: newCert.Cert, Key: string(privateKey)}
			vaultSecretPath := fmt.Sprintf("%s/%s/%s/%s", GlobalConfig.Storage.Vault.CertPrefix, newCert.Owner, newCert.Issuer, newCert.Domain)
			err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to backup certificate", "err", err)
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate and private key for domain '%s' backed up in vault", newCert.Domain))
		}

		if GlobalConfig.Common.CertDeploy {
			hasChange = true
			err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+certData.Issuer, GlobalConfig.Common.CertDirPerm)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}
			err = createLocalPrivateKeyFile(keyFilePath, privateKey)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err)
				continue
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file for domain '%s' created", newCert.Domain))

			err = createLocalCertificateFile(newCert)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err)
				continue
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file for domain '%s' created", newCert.Domain))
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		}
	}

	for _, certData := range diff.Update {
		var privateKey []byte
		keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt

		var privateKeyPath string
		if GlobalConfig.Common.CertKeyFileNoGen {
			if !utils.FileExists(keyFilePath) {
				hasErrors = true
				_ = level.Error(logger).Log("err", fmt.Errorf("local private key file '%s' doesn't exists", keyFilePath))
				continue
			}
			privateKeyPath = keyFilePath
		}

		if certData.CSR == "" || privateKeyPath == "" {
			var san []string
			if certData.SAN != "" {
				san = strings.Split(certData.SAN, ",")
			}
			var err error
			certData.CSR, privateKey, err = utils.GenerateCSRAndPrivateKey(privateKeyPath, certData.Domain, san)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err)
				continue
			}
		}

		certDataBytes, _ := json.Marshal(certData)

		var certParams api.CertificateParams
		err := json.Unmarshal(certDataBytes, &certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err)
			continue
		}

		if GlobalConfig.Common.RevokeOnUpdate {
			certParams.Revoke = true
		}

		newCert, err := acmeClient.UpdateCertificate(certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err)
			continue
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' updated", newCert.Domain))

		if GlobalConfig.Common.CertBackup {
			data := CertBackup{Cert: newCert.Cert, Key: string(privateKey)}
			vaultSecretPath := fmt.Sprintf("%s/%s/%s/%s", GlobalConfig.Storage.Vault.CertPrefix, newCert.Owner, newCert.Issuer, newCert.Domain)
			err = vault.GlobalClient.PutSecretWithAppRole(vaultSecretPath, utils.StructToMapInterface(data))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to backup certificate", "err", err)
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate and private key for domain '%s' backed up in vault", newCert.Domain))
		}

		if (GlobalConfig.Common.CertDeploy && certData.CSR == "") || privateKeyPath == "" {
			hasChange = true
			err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+newCert.Issuer, GlobalConfig.Common.CertDirPerm)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}
			err = createLocalPrivateKeyFile(keyFilePath, privateKey)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err)
				continue
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file for domain '%s' updated", newCert.Domain))

			err = createLocalCertificateFile(newCert)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err)
				continue
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file for domain '%s' updated", newCert.Domain))
			metrics.IncCreatedLocalCertificate(certData.Issuer)
		}
	}

	for _, certData := range diff.Delete {
		var revoke bool
		if GlobalConfig.Common.RevokeOnDelete {
			revoke = true
		}

		err := acmeClient.DeleteCertificate(certData.Issuer, certData.Domain, revoke)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err)
			continue
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' deleted", certData.Domain))

		if GlobalConfig.Common.CertDeploy {
			hasChange = true
			keyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
			err := deleteLocalPrivateKeyFile(keyFilePath)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err)
				continue
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local private key file for domain '%s' deleted", certData.Domain))

			err = deleteLocalCertificateFile(certData.Issuer, certData.Domain)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err)
				continue
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("local certificate file for domain'%s' deleted", certData.Domain))
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
		return fmt.Errorf("Unable to save certificate file %s", certFilePath)
	}
	return nil
}

func deleteLocalCertificateFile(issuer, domain string) error {
	certFilePath := GlobalConfig.Common.CertDir + issuer + "/" + domain + GlobalConfig.Common.CertFileExt
	if utils.FileExists(certFilePath) {
		err := os.Remove(certFilePath)
		if err != nil {
			return fmt.Errorf("Unable to delete certificate file %s", certFilePath)
		}
	}
	return nil
}

func createLocalPrivateKeyFile(keyFilePath string, privateKey []byte) error {
	err := os.WriteFile(keyFilePath, privateKey, GlobalConfig.Common.CertKeyFilePerm)
	if err != nil {
		return fmt.Errorf("Unable to save private key file %s", keyFilePath)
	}
	return nil
}

func deleteLocalPrivateKeyFile(keyFilePath string) error {
	if utils.FileExists(keyFilePath) {
		err := os.Remove(keyFilePath)
		if err != nil {
			return fmt.Errorf("Unable to delete private key file %s", keyFilePath)
		}
	}
	return nil
}

func CheckCertificate(logger log.Logger, GlobalConfigPath string, acmeClient *restclient.Client) {
	newConfigBytes, err := os.ReadFile(filepath.Clean(GlobalConfigPath))
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to read file %s", GlobalConfigPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}
	var cfg Config
	err = yaml.Unmarshal(newConfigBytes, &cfg)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Ignoring file changes %s because of error", GlobalConfigPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}
	GlobalConfig = cfg
	metrics.SetCertificateConfigError(0)

	_ = level.Info(logger).Log("msg", "Checking certificates from config file with remote server")

	old, err := acmeClient.GetAllCertificateMetadata()
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	var newCertList []certstore.Certificate
	var hasChange bool

	for _, certData := range GlobalConfig.Certificate {

		err := utils.CreateNonExistingFolder(GlobalConfig.Common.CertDir+certData.Issuer, GlobalConfig.Common.CertDirPerm)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}

		// Setting default days
		if certData.Days == 0 {
			certData.Days = GlobalConfig.Common.CertDays
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
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Local certificate file '%s' doesn't exists", certFilePath))
				certificate, err := acmeClient.ReadCertificate(certData)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}
				err = createLocalCertificateFile(certificate)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}
				hasChange = true
				_ = level.Warn(logger).Log("msg", fmt.Sprintf("Local certificate file '%s' restored.", certFilePath))
				metrics.IncCreatedLocalCertificate(certData.Issuer)
			} else {
				var currentCertBytes []byte
				currentCertBytes, err = os.ReadFile(filepath.Clean(certFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}

				var err error
				var certificate certstore.CertMap

				if utils.GenerateFingerprint(currentCertBytes) != old[idx].Fingerprint {

					certificate, err = acmeClient.ReadCertificate(certData)
					if err != nil {
						_ = level.Error(logger).Log("err", err)
						continue
					}

					err = os.WriteFile(certFilePath, []byte(certificate.Cert), GlobalConfig.Common.CertFilePerm)
					if err != nil {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save local certificate file %s", certFilePath), "err", err)
					} else {
						hasChange = true
						_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed local certificate %s", certFilePath))
						metrics.IncCreatedLocalCertificate(certData.Issuer)
					}
				}
			}

			certKeyFilePath := GlobalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + GlobalConfig.Common.CertKeyFileExt
			certKeyFileExists := utils.FileExists(certKeyFilePath)

			if !certKeyFileExists && GlobalConfig.Common.CertBackup {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Local certificate key file '%s' doesn't exists", certKeyFilePath))
				toRecreate, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Domain)
			} else if !certKeyFileExists {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf("Certificate key file '%s' doesn't exists. Recreation needed.", certKeyFilePath))
			} else {
				certBytes, err := os.ReadFile(certFilePath)
				if err != nil {
					toRecreate = true
					_ = level.Error(logger).Log("err", err)
					continue
				}

				certKeyBytes, err := os.ReadFile(certKeyFilePath)
				if err != nil {
					toRecreate = true
					_ = level.Error(logger).Log("err", err)
					continue
				}

				_, err = tls.X509KeyPair(certBytes, certKeyBytes)
				if err != nil {
					if GlobalConfig.Common.CertBackup {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("Private key file '%s' and certificate file '%s' error. Restoration needed.", certKeyFilePath, certFilePath), "err", err)
						toRecreate, hasChange = getPrivateKeyFromVault(logger, certKeyFilePath, certFilePath, certData.Issuer, certData.Domain)
					} else {
						toRecreate = true
						_ = level.Error(logger).Log("msg", fmt.Sprintf("Private key file '%s' and certificate file '%s' error. Recreation needed.", certKeyFilePath, certFilePath), "err", err)
					}
				}
			}

			if certData.SAN != old[idx].SAN {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate issuer '%s' for domain '%s' SAN changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].SAN,
					certData.SAN,
				))
			}
			if certData.Days != old[idx].Days {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate issuer '%s' for domain '%s' days changed from '%d' to '%d'.",
					certData.Issuer,
					certData.Domain,
					old[idx].Days,
					certData.Days,
				))
			}
			if certData.Bundle != old[idx].Bundle {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate issuer '%s' for domain '%s' bundle changed from '%v' to '%v'.",
					certData.Issuer,
					certData.Domain,
					old[idx].Bundle,
					certData.Bundle,
				))
			}
			if certData.DNSChallenge != old[idx].DNSChallenge {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate issuer '%s' for domain '%s' dns_challenge changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].DNSChallenge,
					certData.DNSChallenge,
				))
			}
			if certData.HTTPChallenge != old[idx].HTTPChallenge {
				toRecreate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate issuer '%s' for domain '%s' http_challenge changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].HTTPChallenge,
					certData.HTTPChallenge,
				))
			}
			if certData.RenewalDays != old[idx].RenewalDays {
				toUpdate = true

				if !toRecreate {
					tmp = old[idx]
					tmp.RenewalDays = certData.RenewalDays
				}
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate issuer '%s' for domain '%s' renewal_days changed from '%d' to '%d'.",
					certData.Issuer,
					certData.Domain,
					old[idx].RenewalDays,
					certData.RenewalDays,
				))
			}
			if certData.Labels != old[idx].Labels {
				toUpdate = true

				if !toRecreate {
					tmp = old[idx]
					tmp.Labels = certData.Labels
				}
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate issuer '%s' for domain '%s' labels changed from '%s' to '%s'.",
					certData.Issuer,
					certData.Domain,
					old[idx].Labels,
					certData.Labels,
				))
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

			return out.String(), cmd.Run()
		}

		out, err := run(cmdPath, cmdArgs, cmdTimeout)
		if err != nil {
			metrics.IncRunFailedLocalCmd()
			return fmt.Errorf("Command '%s %s' failed: %s. Error: %s", cmdPath, strings.Join(cmdArgs, " "), out, err.Error())
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Command '%s %s' successfully executed", cmdPath, strings.Join(cmdArgs, " ")))
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
		_ = level.Error(logger).Log("err", err)
		return false, false
	}
	data := MapInterfaceToCertBackup(secret)

	if data.Key != "" {
		certBytes, err := os.ReadFile(certFilePath)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return true, false
		}

		_, err = tls.X509KeyPair(certBytes, []byte(data.Key))
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Private key file '%s' and certificate file '%s' error. Recreation needed.", certKeyFilePath, certFilePath), "err", err)
			return true, false
		}
		err = createLocalPrivateKeyFile(certKeyFilePath, []byte(data.Key))
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return true, false
		}
		_ = level.Warn(logger).Log("msg", fmt.Sprintf("Private key file '%s' restored.", certKeyFilePath))
		return false, true
	}
	_ = level.Info(logger).Log("msg", fmt.Sprintf("Certificate key file '%s' doesn't exists. Recreation needed.", certKeyFilePath))
	return true, false
}
