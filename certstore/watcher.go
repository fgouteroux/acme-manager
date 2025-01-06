package certstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/cmd"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"

	"gopkg.in/yaml.v3"
)

func WatchConfigFileChanges(logger log.Logger, interval time.Duration, configPath string) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		newConfigBytes, err := os.ReadFile(filepath.Clean(configPath))
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to read file %s", configPath), "err", err)
			continue
		}
		var cfg config.Config
		err = yaml.Unmarshal(newConfigBytes, &cfg)
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Ignoring file changes %s because of error", configPath), "err", err)
			continue
		}

		oldConfigBytes, err := yaml.Marshal(config.GlobalConfig)
		if err != nil {
			_ = level.Error(logger).Log("msg", "Unable to yaml marshal the globalconfig", "err", err)
			continue
		}

		// no need to check err as umarhsall before
		newConfigBytes, _ = yaml.Marshal(cfg)

		if string(oldConfigBytes) != string(newConfigBytes) {
			_ = level.Info(logger).Log("msg", "modified file", "name", configPath)

			err = Setup(logger, cfg)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Ignoring issuer changes in file %s because of error", configPath), "err", err)
				metrics.SetConfigError(1)
				continue
			}

			vault.GlobalClient, err = vault.InitClient(cfg.Storage.Vault)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Ignoring vault changes in file %s because of error", configPath), "err", err)
				continue
			}
			config.GlobalConfig = cfg
			metrics.IncConfigReload()
			metrics.SetConfigError(0)
		}
	}
}

func WatchCertificateFileChanges(logger log.Logger, interval time.Duration, configPath string) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if isLeaderNow {

			newConfigBytes, err := os.ReadFile(filepath.Clean(configPath))
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to read file %s", configPath), "err", err)
				metrics.SetCertificateConfigError(1)
				continue
			}
			var cfg cert.Config
			err = yaml.Unmarshal(newConfigBytes, &cfg)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Ignoring file changes %s because of error", configPath), "err", err)
				metrics.SetCertificateConfigError(1)
				continue
			}

			oldConfigBytes, err := yaml.Marshal(certConfig)
			if err != nil {
				_ = level.Error(logger).Log("msg", "Unable to yaml marshal the certConfig", "err", err)
				continue
			}

			metrics.SetCertificateConfigError(0)

			// no need to check err as umarshall before
			newConfigBytes, _ = yaml.Marshal(cfg)

			if string(oldConfigBytes) != string(newConfigBytes) {
				_ = level.Info(logger).Log("msg", "modified file", "name", configPath)

				old, _ := AmStore.GetKVRingCert(AmRingKey)

				var newCertList []cert.Certificate
				for _, certData := range cfg.Certificate {
					// Setting default days
					if certData.Days == 0 {
						certData.Days = config.GlobalConfig.Common.CertDays
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

				diff, hasChanged := CheckCertDiff(old, newCertList, logger)

				if hasChanged {
					certInfo, err := applyCertFileChanges(diff, logger)
					if err == nil {
						localCache.Set(AmRingKey, certInfo)
						AmStore.PutKVRing(AmRingKey, certInfo)
						certConfig = cfg
						metrics.IncCertificateConfigReload()
					} else {
						_ = level.Error(logger).Log("err", err)
					}
				}
			}
		}
	}
}

func WatchLocalCertificate(logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		err := CheckAndDeployLocalCertificate(AmStore, logger)
		if err != nil {
			_ = level.Error(logger).Log("msg", "Check local certificate failed", "err", err)
		}
	}
}

func WatchRingKvStoreCertChanges(logger log.Logger) {
	AmStore.RingConfig.KvStore.WatchKey(context.Background(), AmRingKey, ring.JSONCodec, func(in interface{}) bool {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if !isLeaderNow {
			val := in.(*ring.Data)
			var newCertList []cert.Certificate
			_ = json.Unmarshal([]byte(val.Content), &newCertList)

			old, found := localCache.Get(AmRingKey)
			if !found {
				_ = level.Error(logger).Log("msg", "Empty local cache store")
			} else {
				diff, hasChanged := CheckCertDiff(old.Value.([]cert.Certificate), newCertList, logger)

				if hasChanged {
					_ = level.Info(logger).Log("msg", "kv store key changes")

					if config.GlobalConfig.Common.CertDeploy {
						applyRingKvStoreChanges(diff, logger)
					}
					localCache.Set(AmRingKey, newCertList)

					if config.GlobalConfig.Common.CmdEnabled {
						cmd.Execute(logger, config.GlobalConfig.Common)
					}
				} else {
					_ = level.Info(logger).Log("msg", "kv store key no changes")
				}
			}
		}

		return true // yes, keep watching
	})
}

func WatchCertExpiration(logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if isLeaderNow {
			err := CheckCertExpiration(AmStore, logger)
			if err != nil {
				_ = level.Error(logger).Log("msg", "Certificate check renewal failed", "err", err)
			}
		}
	}
}

func WatchAPICertExpiration(logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if isLeaderNow {
			err := CheckAPICertExpiration(AmStore, logger)
			if err != nil {
				_ = level.Error(logger).Log("msg", "Certificate check renewal failed", "err", err)
			}
		}
	}
}

func WatchTokenExpiration(logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if isLeaderNow {
			data, err := AmStore.GetKVRingToken(TokenRingKey)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
			}
			var hasChange bool
			for tokenID, tokenData := range data {

				if tokenData.Expires == "Never" {
					continue
				}
				layout := "2006-01-02 15:04:05 -0700 MST"
				t, err := time.Parse(layout, tokenData.Expires)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					continue
				}

				if time.Now().After(t) {
					secretKeyPathPrefix := config.GlobalConfig.Storage.Vault.TokenPrefix
					if secretKeyPathPrefix == "" {
						secretKeyPathPrefix = "token"
					}

					secretKeyPath := fmt.Sprintf("%s/%s/%s", secretKeyPathPrefix, tokenData.Username, tokenID)
					err = vault.GlobalClient.DeleteSecretWithAppRole(secretKeyPath)
					if err != nil {
						_ = level.Error(logger).Log("err", err)
						continue
					}
					hasChange = true
					delete(data, tokenID)
				}
			}
			if hasChange {
				// udpate kv store
				AmStore.PutKVRing(TokenRingKey, data)
			}
		}
	}
}
