package client

import (
	"bytes"
	"context"
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

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/restclient"
	"github.com/fgouteroux/acme_manager/utils"

	"gopkg.in/yaml.v3"
)

var (
	config Config
)

type MapDiff struct {
	Create   []certstore.Certificate `json:"create"`
	Update   []certstore.Certificate `json:"update"`
	Delete   []certstore.Certificate `json:"delete"`
	Unchange []certstore.Certificate `json:"unchange"`
}

func CheckAndDeployLocalCertificate(logger log.Logger, acmeClient *restclient.Client) {
	if !config.Common.CertDeploy {
		return
	}

	certificates, err := acmeClient.GetAllCertificateMetadata()
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}
	var hasChange bool
	for _, certData := range config.Certificate {

		certFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
		keyFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

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
				err := utils.CreateNonExistingFolder(config.Common.CertDir+certData.Issuer, config.Common.CertDirPerm)
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
				err := utils.CreateNonExistingFolder(config.Common.CertDir+certData.Issuer, config.Common.CertDirPerm)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}
			}

			idx := slices.IndexFunc(certificates, func(c certstore.Certificate) bool {
				return c.Domain == certData.Domain && c.Issuer == certData.Issuer
			})

			if idx == -1 {
				_ = level.Info(logger).Log("msg", fmt.Errorf("Certificate '%s' with issuer '%s' not found", certData.Domain, certData.Issuer))
				continue
			}

			var err error
			var certificate certstore.CertMap

			if utils.GenerateFingerprint(currentCertBytes) != certificates[idx].Fingerprint {
				hasChange = true
				certificate, err = acmeClient.ReadCertificate(certData)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}

				err = os.WriteFile(certFilePath, []byte(certificate.Cert), config.Common.CertFilePerm)
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

				err = os.WriteFile(keyFilePath, []byte(certificate.Key), config.Common.CertKeyFilePerm)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
				} else {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath))
				}
			}
		}
	}

	if hasChange && config.Common.CmdEnabled {
		executeCommand(logger, config.Common)
	}
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
			// key unchanged
		} else if idx >= 0 {
			diff.Unchange = append(diff.Unchange, oldCert)
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

func applyCertFileChanges(acmeClient *restclient.Client, diff MapDiff, logger log.Logger) error {
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

		if config.Common.CertDeploy {
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
		if config.Common.CertDeploy {
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
		if config.Common.CertDeploy {
			deleteLocalCertificateResource(certstore.CertMap{Certificate: certData}, logger)
		}
	}

	if hasChange && config.Common.CmdEnabled {
		executeCommand(logger, config.Common)
	}

	return nil
}

func createLocalCertificateResource(certData certstore.CertMap, logger log.Logger) {
	folderPath := config.Common.CertDir + certData.Issuer
	err := utils.CreateNonExistingFolder(folderPath, config.Common.CertDirPerm)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}
	certFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
	keyFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

	certBytes := []byte(certData.Cert)
	err = os.WriteFile(certFilePath, certBytes, config.Common.CertFilePerm)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath))
		metrics.IncCreatedLocalCertificate(certData.Issuer)
	}

	keyBytes := []byte(certData.Key)
	err = os.WriteFile(keyFilePath, keyBytes, config.Common.CertKeyFilePerm)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed private key %s", keyFilePath))
	}
}

func deleteLocalCertificateResource(certData certstore.CertMap, logger log.Logger) {
	certFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
	keyFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

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

	var newCertList []certstore.Certificate
	for _, certData := range cfg.Certificate {

		// Setting default days
		if certData.Days == 0 {
			certData.Days = cfg.Common.CertDays
		}

		idx := slices.IndexFunc(old, func(c certstore.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer
		})

		if idx == -1 {
			newCertList = append(newCertList, certData)
		} else {
			var toUpdate bool
			if certData.RenewalDays != old[idx].RenewalDays {
				toUpdate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate '%s' renewal_days changed from '%d' to '%d'.",
					certData.Domain,
					old[idx].RenewalDays,
					certData.RenewalDays,
				))
			}
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
			if certData.DNSChallenge != old[idx].DNSChallenge {
				toUpdate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate '%s' dns_challenge changed from '%s' to '%s'.",
					certData.Domain,
					old[idx].DNSChallenge,
					certData.DNSChallenge,
				))
			}
			if certData.HTTPChallenge != old[idx].HTTPChallenge {
				toUpdate = true
				_ = level.Info(logger).Log("msg", fmt.Sprintf(
					"Certificate '%s' http_challenge changed from '%s' to '%s'.",
					certData.Domain,
					old[idx].HTTPChallenge,
					certData.HTTPChallenge,
				))
			}

			if toUpdate {
				newCertList = append(newCertList, certData)
			} else {
				newCertList = append(newCertList, old[idx])
			}
		}
	}

	diff, hasChanged := checkCertDiff(old, newCertList, logger)

	if hasChanged {
		err := applyCertFileChanges(acmeClient, diff, logger)
		if err == nil {
			config = cfg
			metrics.IncCertificateConfigReload()
		} else {
			_ = level.Error(logger).Log("err", err)
		}
	} else {
		config = cfg
	}
}

func executeCommand(logger log.Logger, cfg Common) {
	cmdArr := strings.Split(cfg.CmdRun, " ")
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

	out, err := run(cmdPath, cmdArgs, cfg.CmdTimeout)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Command '%s %s' failed: %s", cmdPath, strings.Join(cmdArgs, " "), out), "err", err)
		metrics.IncRunFailedLocalCmd()
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Command '%s %s' successfully executed", cmdPath, strings.Join(cmdArgs, " ")))
		metrics.IncRunSuccessLocalCmd()
	}
}
