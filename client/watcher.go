package client

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/restclient"

	"gopkg.in/yaml.v3"
)

func WatchCertificateFileChanges(logger log.Logger, interval time.Duration, configPath string, acmeClient *restclient.Client) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		err := CheckAndDeployLocalCertificate(logger, configPath, acmeClient)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
		}
	}
}

func WatchConfigFileChanges(logger log.Logger, interval time.Duration, configPath string, acmeClient *restclient.Client) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {

		newConfigBytes, err := os.ReadFile(filepath.Clean(configPath))
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to read file %s", configPath), "err", err)
			metrics.SetCertificateConfigError(1)
			continue
		}
		var cfg Config
		err = yaml.Unmarshal(newConfigBytes, &cfg)
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Ignoring file changes %s because of error", configPath), "err", err)
			metrics.SetCertificateConfigError(1)
			continue
		}

		oldConfigBytes, err := yaml.Marshal(certConfig)
		if err != nil {
			_ = level.Error(logger).Log("msg", "Unable to yaml marshal the config", "err", err)
			continue
		}

		metrics.SetCertificateConfigError(0)

		// no need to check err as umarshall before
		newConfigBytes, _ = yaml.Marshal(cfg)

		if string(oldConfigBytes) != string(newConfigBytes) {
			_ = level.Info(logger).Log("msg", "modified file", "name", configPath)

			old, err := acmeClient.GetAllCertificateMetadata()
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			var newCertList []cert.Certificate
			for _, certData := range cfg.Certificate {
				// Setting default days
				if certData.Days == 0 {
					certData.Days = certConfig.Common.CertDays
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
	}
}
