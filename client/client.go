package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/cmd"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/restclient"
	"github.com/fgouteroux/acme_manager/utils"

	"gopkg.in/yaml.v3"
)

var (
	certConfig Config
)

func CheckAndDeployLocalCertificate(logger log.Logger, configPath string, acmeClient *restclient.Client) error {
	configBytes, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return err
	}

	var cfg Config
	err = yaml.Unmarshal(configBytes, &cfg)
	if err != nil {
		return err
	}
	metrics.SetCertificateConfigError(0)

	_ = level.Info(logger).Log("msg", "Checking certificates from config file")

	certConfig = cfg

	var hasChange bool
	certStat := make(map[string]float64)
	for _, certData := range cfg.Certificate {

		certFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
		keyFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

		certMap, err := acmeClient.ReadCertificate(certData)
		if err != nil && !strings.Contains(err.Error(), "404 Not Found") {
			_ = level.Error(logger).Log("err", err)
			continue
		}

		var certificate Certificate
		if certMap == nil {
			newCertMap, err := acmeClient.CreateCertificate(certData)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			certificate = mapToCertificate(newCertMap)
		} else {
			certificate = mapToCertificate(certMap)
		}

		certStat[certData.Issuer] += 1.0

		certFileExists := utils.FileExists(certFilePath)
		keyFileExists := utils.FileExists(keyFilePath)

		if !certFileExists && !keyFileExists {
			hasChange = true
			createLocalCertificateResource(certificate, logger)
		} else {
			var currentCertBytes, currentKeyBytes []byte
			if certFileExists {
				currentCertBytes, err = os.ReadFile(filepath.Clean(certFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err)
				}
			} else {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Certificate file %s doesn't exists", certFilePath))
				err := utils.CreateNonExistingFolder(certConfig.Common.CertDir+certData.Issuer, certConfig.Common.CertDirPerm)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}
			}

			if keyFileExists {
				currentKeyBytes, err = os.ReadFile(filepath.Clean(keyFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err)
				}
			} else {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Private key file %s doesn't exists", keyFilePath))
				err := utils.CreateNonExistingFolder(certConfig.Common.CertDir+certData.Issuer, certConfig.Common.CertDirPerm)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}
			}

			certBytes, _ := base64.StdEncoding.DecodeString(certificate.Cert)
			if utils.GenerateFingerprint(currentCertBytes) != utils.GenerateFingerprint(certBytes) {
				hasChange = true
				err = os.WriteFile(certFilePath, certBytes, certConfig.Common.CertFilePerm)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err)
				} else {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath))
					metrics.IncCreatedLocalCertificate(certData.Issuer)
				}
			}

			keyBytes, _ := base64.StdEncoding.DecodeString(certificate.Key)
			if utils.GenerateFingerprint(currentKeyBytes) != utils.GenerateFingerprint(keyBytes) {
				hasChange = true
				err = os.WriteFile(keyFilePath, keyBytes, certConfig.Common.CertKeyFilePerm)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
				} else {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath))
				}
			}
		}
	}

	for issuer, count := range certStat {
		metrics.SetManagedCertificate(issuer, count)
	}
	if hasChange && certConfig.Common.CmdEnabled {
		cmd.Execute(logger, certConfig.Common)
	}
	return nil
}

func applyCertFileChanges(acmeClient *restclient.Client, diff certstore.MapDiff, logger log.Logger) error {
	var hasChange bool
	for _, certData := range diff.Create {
		hasChange = true
		newCertMap, err := acmeClient.CreateCertificate(certData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}

		newCert := mapToCertificate(newCertMap)
		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' created", newCert.Domain))
		metrics.IncManagedCertificate(certData.Issuer)

		if certConfig.Common.CertDeploy {
			createLocalCertificateResource(newCert, logger)
		}
	}

	for _, certData := range diff.Update {
		hasChange = true
		newCertMap, err := acmeClient.UpdateCertificate(certData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}
		newCert := mapToCertificate(newCertMap)
		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' updated", newCert.Domain))
		if certConfig.Common.CertDeploy {
			deleteLocalCertificateResource(newCert, logger)
			createLocalCertificateResource(newCert, logger)
		}
	}

	for _, certData := range diff.Delete {
		hasChange = true
		oldCertMap, err := acmeClient.UpdateCertificate(certData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}
		oldCert := mapToCertificate(oldCertMap)
		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' deleted", oldCert.Domain))
		metrics.DecManagedCertificate(certData.Issuer)
		if certConfig.Common.CertDeploy {
			deleteLocalCertificateResource(oldCert, logger)
		}
	}

	if hasChange && certConfig.Common.CmdEnabled {
		cmd.Execute(logger, certConfig.Common)
	}

	return nil
}

func mapToCertificate(m map[string]interface{}) Certificate {
	// convert map to json
	jsonString, _ := json.Marshal(m)

	// convert json to struct
	var s Certificate
	_ = json.Unmarshal(jsonString, &s)
	return s
}

func createLocalCertificateResource(certData Certificate, logger log.Logger) {
	folderPath := certConfig.Common.CertDir + certData.Issuer
	err := utils.CreateNonExistingFolder(folderPath, certConfig.Common.CertDirPerm)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}
	certFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
	keyFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

	certBytes, _ := base64.StdEncoding.DecodeString(certData.Cert)

	err = os.WriteFile(certFilePath, certBytes, certConfig.Common.CertFilePerm)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath))
		metrics.IncCreatedLocalCertificate(certData.Issuer)
	}

	keyBytes, _ := base64.StdEncoding.DecodeString(certData.Key)
	err = os.WriteFile(keyFilePath, keyBytes, certConfig.Common.CertKeyFilePerm)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath))
	}
}

func deleteLocalCertificateResource(certData Certificate, logger log.Logger) {
	certFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
	keyFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

	err := os.Remove(certFilePath)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to delete certificate file %s", certFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Removed certificate %s", certFilePath))
		metrics.IncDeletedLocalCertificate(certData.Issuer)
	}

	err = os.Remove(keyFilePath)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to delete private key file %s", keyFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Removed private key %s", keyFilePath))
	}
}
