package client

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	cert "github.com/fgouteroux/acme_manager/certificate"
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

func CheckAndDeployLocalCertificate(logger log.Logger, acmeClient *restclient.Client) {
	certificates, err := acmeClient.GetAllCertificateMetadata()
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}
	var hasChange bool
	for _, certData := range certConfig.Certificate {

		certFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
		keyFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

		certFileExists := utils.FileExists(certFilePath)
		keyFileExists := utils.FileExists(keyFilePath)

		if !certFileExists && !keyFileExists {
			hasChange = true
			certificate, err := acmeClient.ReadCertificate(certData)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}
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

			idx := slices.IndexFunc(certificates, func(c cert.Certificate) bool {
				return c.Domain == certData.Domain && c.Issuer == certData.Issuer
			})

			if idx == -1 {
				_ = level.Info(logger).Log("msg", fmt.Errorf("Certificate '%s' with issuer '%s' not found", certData.Domain, certData.Issuer))
				continue
			}

			var err error
			var certificate cert.CertMap

			if utils.GenerateFingerprint(currentCertBytes) != certificates[idx].Fingerprint {
				hasChange = true
				certificate, err = acmeClient.ReadCertificate(certData)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}

				err = os.WriteFile(certFilePath, []byte(certificate.Cert), certConfig.Common.CertFilePerm)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err)
				} else {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath))
					metrics.IncCreatedLocalCertificate(certData.Issuer)
				}
			}

			if utils.GenerateFingerprint(currentKeyBytes) != certificates[idx].KeyFingerprint {
				hasChange = true

				// check if read certificate have not been called previously
				if certificate.Owner == "" {
					certificate, err = acmeClient.ReadCertificate(certData)
					if err != nil {
						_ = level.Error(logger).Log("err", err)
						continue
					}
				}

				err = os.WriteFile(keyFilePath, []byte(certificate.Key), certConfig.Common.CertKeyFilePerm)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
				} else {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath))
				}
			}
		}
	}

	if hasChange && certConfig.Common.CmdEnabled {
		cmd.Execute(logger, certConfig.Common)
	}
}

func applyCertFileChanges(acmeClient *restclient.Client, diff certstore.MapDiff, logger log.Logger) error {
	var hasChange bool
	for _, certData := range diff.Create {
		hasChange = true
		newCert, err := acmeClient.CreateCertificate(certData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}

		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' created", newCert.Domain))
		metrics.IncManagedCertificate(certData.Issuer)

		if certConfig.Common.CertDeploy {
			createLocalCertificateResource(newCert, logger)
		}
	}

	for _, certData := range diff.Update {
		hasChange = true
		newCert, err := acmeClient.UpdateCertificate(certData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' updated", newCert.Domain))
		if certConfig.Common.CertDeploy {
			deleteLocalCertificateResource(newCert, logger)
			createLocalCertificateResource(newCert, logger)
		}
	}

	for _, certData := range diff.Delete {
		hasChange = true
		err := acmeClient.DeleteCertificate(certData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' deleted", certData.Domain))
		metrics.DecManagedCertificate(certData.Issuer)
		if certConfig.Common.CertDeploy {
			deleteLocalCertificateResource(cert.CertMap{Issuer: certData.Issuer, Domain: certData.Domain}, logger)
		}
	}

	if hasChange && certConfig.Common.CmdEnabled {
		cmd.Execute(logger, certConfig.Common)
	}

	return nil
}

func createLocalCertificateResource(certData cert.CertMap, logger log.Logger) {
	folderPath := certConfig.Common.CertDir + certData.Issuer
	err := utils.CreateNonExistingFolder(folderPath, certConfig.Common.CertDirPerm)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}
	certFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
	keyFilePath := certConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

	certBytes := []byte(certData.Cert)
	err = os.WriteFile(certFilePath, certBytes, certConfig.Common.CertFilePerm)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath))
		metrics.IncCreatedLocalCertificate(certData.Issuer)
	}

	keyBytes := []byte(certData.Key)
	err = os.WriteFile(keyFilePath, keyBytes, certConfig.Common.CertKeyFilePerm)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath))
	}
}

func deleteLocalCertificateResource(certData cert.CertMap, logger log.Logger) {
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

func CheckCertificate(logger log.Logger, configPath string, acmeClient *restclient.Client) {
	newConfigBytes, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to read file %s", configPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}
	var cfg Config
	err = yaml.Unmarshal(newConfigBytes, &cfg)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Ignoring file changes %s because of error", configPath), "err", err)
		metrics.SetCertificateConfigError(1)
		return
	}

	metrics.SetCertificateConfigError(0)

	_ = level.Info(logger).Log("msg", "Checking certificates from config file with remote server")

	old, err := acmeClient.GetAllCertificateMetadata()
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	var newCertList []cert.Certificate
	for _, certData := range cfg.Certificate {

		// Setting default days
		if certData.Days == 0 {
			certData.Days = cfg.Common.CertDays
		}

		idx := slices.IndexFunc(old, func(c cert.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer
		})

		if idx == -1 {
			newCertList = append(newCertList, certData)
		} else {

			// Ignoring this field
			certData.RenewalDays = 0

			var toUpdate bool
			if certData.SAN != old[idx].SAN {
				toUpdate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate '%s' SAN changed from '%s' to '%s'.",
					certData.Domain,
					old[idx].SAN,
					certData.SAN,
				))
			}
			if certData.Days != old[idx].Days {
				toUpdate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate '%s' days changed from '%d' to '%d'.",
					certData.Domain,
					old[idx].Days,
					certData.Days,
				))
			}
			if certData.Bundle != old[idx].Bundle {
				toUpdate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate '%s' bundle changed from '%v' to '%v'.",
					certData.Domain,
					old[idx].Bundle,
					certData.Bundle,
				))
			}

			if toUpdate {
				newCertList = append(newCertList, certData)
			} else {
				newCertList = append(newCertList, old[idx])
			}
		}
	}

	diff, hasChanged := certstore.CheckCertDiff(old, newCertList, logger)

	if hasChanged {
		err := applyCertFileChanges(acmeClient, diff, logger)
		if err == nil {
			certConfig = cfg
			metrics.IncCertificateConfigReload()
		} else {
			_ = level.Error(logger).Log("err", err)
		}
	} else {
		certConfig = cfg
	}
}
