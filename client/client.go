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

	"github.com/fgouteroux/acme_manager/api"
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
	Create []certstore.Certificate `json:"create"`
	Update []certstore.Certificate `json:"update"`
	Delete []certstore.Certificate `json:"delete"`
}

func CheckAndDeployLocalCertificate(logger log.Logger, acmeClient *restclient.Client) {
	if !config.Common.CertDeploy {
		return
	}

	_ = level.Info(logger).Log("msg", "Checking local certificates with remote server")
	certificates, err := acmeClient.GetAllCertificateMetadata()
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	certStat := make(map[string]float64)
	for _, certificate := range certificates {
		certStat[certificate.Issuer] += 1.0
	}

	for issuer, count := range certStat {
		metrics.SetManagedCertificate(issuer, "", count)
	}

	var hasChange bool
	for _, certData := range config.Certificate {

		err := utils.CreateNonExistingFolder(config.Common.CertDir+certData.Issuer, config.Common.CertDirPerm)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}

		certFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
		certFileExists := utils.FileExists(certFilePath)

		if !certFileExists {
			hasChange = true
			certificate, err := acmeClient.ReadCertificate(certData)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}
			createLocalCertificateResource(certificate, logger)
		} else {

			var currentCertBytes []byte
			if certFileExists {
				currentCertBytes, err = os.ReadFile(filepath.Clean(certFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err)
				}
			} else {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Certificate file %s doesn't exists", certFilePath))
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
		}
	}

	if hasChange && config.Common.CmdEnabled {
		err = executeCommand(logger, config.Common, false)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
		}
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

	if config.Common.CmdEnabled {
		err := executeCommand(logger, config.Common, true)
		if err != nil {
			_ = level.Error(logger).Log("msg", "Skipping changes because pre_cmd failed", "err", err)
			return
		}
	}

	var hasErrors bool
	for _, certData := range diff.Create {

		keyFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"
		var san []string
		if certData.SAN != "" {
			san = strings.Split(certData.SAN, ",")
		}
		csr, privateKey, err := utils.GenerateCSRAndPrivateKey(certData.Domain, san)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err)
			continue
		}

		err = os.WriteFile(keyFilePath, privateKey, config.Common.CertKeyFilePerm)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
			continue
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Created private key %s", keyFilePath))

		certData.CSR = string(csr)

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

		if config.Common.CertDeploy {
			createLocalCertificateResource(newCert, logger)
		}
	}

	for _, certData := range diff.Update {

		if certData.CSR == "" {
			keyFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"
			var san []string
			if certData.SAN != "" {
				san = strings.Split(certData.SAN, ",")
			}
			csr, privateKey, err := utils.GenerateCSRAndPrivateKey(certData.Domain, san)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("err", err)
				continue
			}

			err = os.WriteFile(keyFilePath, privateKey, config.Common.CertKeyFilePerm)
			if err != nil {
				hasErrors = true
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
				continue
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Updated private key %s", keyFilePath))

			certData.CSR = string(csr)
		}

		certDataBytes, _ := json.Marshal(certData)

		var certParams api.CertificateParams
		err := json.Unmarshal(certDataBytes, &certParams)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err)
			continue
		}

		if config.Common.RevokeOnUpdate {
			certParams.Revoke = true
		}

		newCert, err := acmeClient.UpdateCertificate(certParams)
		if err != nil {
			hasErrors = true
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
		var revoke bool
		if config.Common.RevokeOnDelete {
			revoke = true
		}

		err := acmeClient.DeleteCertificate(certData.Issuer, certData.Domain, revoke)
		if err != nil {
			hasErrors = true
			_ = level.Error(logger).Log("err", err)
			continue
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("certificate '%s' deleted", certData.Domain))

		if config.Common.CertDeploy {
			deleteLocalCertificateResource(certstore.CertMap{Certificate: certData}, logger)
		}
	}

	if !hasErrors && config.Common.CmdEnabled {
		err := executeCommand(logger, config.Common, false)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
		}
	}
}

func createLocalCertificateResource(certData certstore.CertMap, logger log.Logger) {
	folderPath := config.Common.CertDir + certData.Issuer
	err := utils.CreateNonExistingFolder(folderPath, config.Common.CertDirPerm)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}
	certFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"

	certBytes := []byte(certData.Cert)
	err = os.WriteFile(certFilePath, certBytes, config.Common.CertFilePerm)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Deployed certificate %s", certFilePath))
		metrics.IncCreatedLocalCertificate(certData.Issuer)
	}
}

func deleteLocalCertificateResource(certData certstore.CertMap, logger log.Logger) {
	certFilePath := config.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"

	err := os.Remove(certFilePath)
	if err != nil {
		_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to delete certificate file %s", certFilePath), "err", err)
	} else {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Removed certificate %s", certFilePath))
		metrics.IncDeletedLocalCertificate(certData.Issuer)
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
	config = cfg
	metrics.SetCertificateConfigError(0)

	_ = level.Info(logger).Log("msg", "Checking certificates from config file with remote server")

	old, err := acmeClient.GetAllCertificateMetadata()

	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return
	}

	var newCertList []certstore.Certificate

	for _, certData := range cfg.Certificate {

		err := utils.CreateNonExistingFolder(config.Common.CertDir+certData.Issuer, config.Common.CertDirPerm)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}

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
			var toRecreate bool

			var tmp certstore.Certificate

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
