package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/account"
	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/ring"

	"gopkg.in/yaml.v3"
)

func WatchConfigFileChanges(logger log.Logger, interval time.Duration, configPath string) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		newConfigBytes, err := os.ReadFile(filepath.Clean(configPath))
		if err != nil {
			level.Error(logger).Log("msg", fmt.Sprintf("Unable to read file %s", configPath), "err", err) // #nosec G104
			continue
		}
		var cfg config.Config
		err = yaml.Unmarshal(newConfigBytes, &cfg)
		if err != nil {
			level.Error(logger).Log("msg", fmt.Sprintf("Ignoring file changes %s because of error", configPath), "err", err) // #nosec G104
			continue
		}

		oldConfigBytes, err := yaml.Marshal(globalConfig)
		if err != nil {
			level.Error(logger).Log("msg", "Unable to yaml marshal the globalconfig", "err", err) // #nosec G104
			continue
		}

		// no need to check err as umarhsall before
		newConfigBytes, _ = yaml.Marshal(cfg)

		if string(oldConfigBytes) != string(newConfigBytes) {
			level.Info(logger).Log("msg", "modified file", "name", configPath) // #nosec G104

			err = account.Setup(logger, cfg)
			if err != nil {
				level.Error(logger).Log("msg", fmt.Sprintf("Ignoring issuer changes in file %s because of error", configPath), "err", err) // #nosec G104
				continue
			}
			globalConfig = cfg
		}
	}
}

func WatchCertificateFileChanges(amStore *CertStore, logger log.Logger, interval time.Duration, configPath string) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(amStore.RingConfig)
		if isLeaderNow {

			newConfigBytes, err := os.ReadFile(filepath.Clean(configPath))
			if err != nil {
				level.Error(logger).Log("msg", fmt.Sprintf("Unable to read file %s", configPath), "err", err) // #nosec G104
				continue
			}
			var cfg cert.Config
			err = yaml.Unmarshal(newConfigBytes, &cfg)
			if err != nil {
				level.Error(logger).Log("msg", fmt.Sprintf("Ignoring file changes %s because of error", configPath), "err", err) // #nosec G104
				continue
			}

			oldConfigBytes, err := yaml.Marshal(certConfig)
			if err != nil {
				level.Error(logger).Log("msg", "Unable to yaml marshal the certConfig", "err", err) // #nosec G104
				continue
			}

			// no need to check err as umarshall before
			newConfigBytes, _ = yaml.Marshal(cfg)

			if string(oldConfigBytes) != string(newConfigBytes) {
				level.Info(logger).Log("msg", "modified file", "name", configPath) // #nosec G104

				old, _ := amStore.GetKVRing()

				var newCertList []cert.Certificate
				for _, certData := range cfg.Certificate {
					// Setting default days
					if certData.Days == 0 {
						certData.Days = *certDays
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
							level.Info(logger).Log("msg", fmt.Sprintf(
								"Certificate '%s' SAN changed from '%s' to '%s'.",
								certData.Domain,
								old[idx].SAN,
								certData.SAN,
							)) // #nosec G104
						}
						if certData.Days != old[idx].Days {
							toUpdate = true
							level.Info(logger).Log("msg", fmt.Sprintf(
								"Certificate '%s' days changed from '%d' to '%d'.",
								certData.Domain,
								old[idx].Days,
								certData.Days,
							)) // #nosec G104
						}
						if certData.Bundle != old[idx].Bundle {
							toUpdate = true
							level.Info(logger).Log("msg", fmt.Sprintf(
								"Certificate '%s' bundle changed from '%v' to '%v'.",
								certData.Domain,
								old[idx].Bundle,
								certData.Bundle,
							)) // #nosec G104
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
					certInfo, err := applyCertFileChanges(diff, logger)
					if err == nil {
						localCache.Set(amRingKey, certInfo)
						amStore.PutKVRing(certInfo)
					} else {
						level.Error(logger).Log("err", err) // #nosec G104
					}
				}
				certConfig = cfg
			}
		}
	}
}
