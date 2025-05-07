package certstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/sirupsen/logrus"

	"github.com/go-acme/lego/v4/certcrypto"

	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"

	"gopkg.in/yaml.v3"
)

func WatchConfigFileChanges(logger log.Logger, interval time.Duration, configPath, version string) {
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

			err = Setup(logger, cfg, version)
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

func WatchCertExpiration(logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if isLeaderNow {
			err := CheckCertExpiration(AmStore, logger, isLeaderNow)
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
			data, err := AmStore.GetKVRingToken(AmTokenRingKey, isLeaderNow)
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
				AmStore.PutKVRing(AmTokenRingKey, data)
			}
		}
	}
}

func WatchIssuerHealth(logger log.Logger, interval time.Duration, version string) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {

		for issuer, issuerConf := range config.GlobalConfig.Issuer {

			issuerError := 1.0
			privateKeyPath := fmt.Sprintf("%s/%s/private_key.pem", config.GlobalConfig.Common.RootPathAccount, issuer)

			privateKeyBytes, err := os.ReadFile(filepath.Clean(privateKeyPath))
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				metrics.SetIssuerConfigError(issuer, issuerError)
				continue
			}
			privateKeyPEM, err := certcrypto.ParsePEMPrivateKey(privateKeyBytes)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Errorf("Unable parse private key '%s'", privateKeyPath), "err", err)
				metrics.SetIssuerConfigError(issuer, issuerError)
				continue
			}

			userAgent := fmt.Sprintf("acme-manager/%s", version)

			// Add the custom hook to the lego logger to add fields
			LegoLogger.AddHook(&CustomLogrusHookIssuerAccount{Issuer: issuer})
			_, _, err = tryRecoverRegistration(privateKeyPEM, issuerConf.Contact, issuerConf.CADirURL, userAgent)
			// Remove the custom hook
			LegoLogger.ReplaceHooks(make(logrus.LevelHooks))
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Errorf("Unable to recover registration account for private key '%s'", privateKeyPath), "err", err)
			}

			metrics.SetIssuerConfigError(issuer, 0.0)

		}
	}
}

func WatchRingKvStoreChanges(ringConfig ring.AcmeManagerRing, logger log.Logger) {
	go ringConfig.KvStore.WatchKey(context.Background(), AmCertificateRingKey, ring.JSONCodec, func(in interface{}) bool {
		isLeaderNow, _ := ring.IsLeader(ringConfig)
		if !isLeaderNow {
			val := in.(*ring.Data)
			localCache.Set(AmCertificateRingKey, val.Content)
			_ = level.Debug(logger).Log("msg", fmt.Sprintf("updated local cache key %s", AmCertificateRingKey)) // #nosec G104
		}
		return true // yes, keep watching
	})

	go ringConfig.KvStore.WatchKey(context.Background(), AmTokenRingKey, ring.JSONCodec, func(in interface{}) bool {
		isLeaderNow, _ := ring.IsLeader(ringConfig)
		if !isLeaderNow {
			val := in.(*ring.Data)
			localCache.Set(AmTokenRingKey, val.Content)
			_ = level.Debug(logger).Log("msg", fmt.Sprintf("updated local cache key %s", AmTokenRingKey)) // #nosec G104
		}
		return true // yes, keep watching
	})

	go ringConfig.KvStore.WatchKey(context.Background(), AmChallengeRingKey, ring.JSONCodec, func(in interface{}) bool {
		isLeaderNow, _ := ring.IsLeader(ringConfig)
		if !isLeaderNow {
			val := in.(*ring.Data)
			localCache.Set(AmChallengeRingKey, val.Content)
			_ = level.Debug(logger).Log("msg", fmt.Sprintf("updated local cache key %s", AmChallengeRingKey)) // #nosec G104
		}
		return true // yes, keep watching
	})
}
