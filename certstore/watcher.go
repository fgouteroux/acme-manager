package certstore

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/sirupsen/logrus"

	"github.com/go-acme/lego/v4/certcrypto"

	"github.com/fgouteroux/acme-manager/config"
	"github.com/fgouteroux/acme-manager/metrics"
	"github.com/fgouteroux/acme-manager/ring"
	"github.com/fgouteroux/acme-manager/storage/vault"

	"gopkg.in/yaml.v3"
)

func WatchConfigFileChanges(logger log.Logger, customLogger *logrus.Logger, interval time.Duration, configPath, version string) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		_ = level.Debug(logger).Log("msg", "check config file changes")
		newConfigBytes, err := os.ReadFile(filepath.Clean(configPath))
		if err != nil {
			_ = level.Error(logger).Log("msg", "unable to read file", "path", configPath, "err", err)
			continue
		}
		var cfg config.Config
		err = yaml.Unmarshal(newConfigBytes, &cfg)
		if err != nil {
			_ = level.Error(logger).Log("msg", "ignoring file changes because of error", "path", configPath, "err", err)
			continue
		}

		oldConfigBytes, err := yaml.Marshal(config.GlobalConfig)
		if err != nil {
			_ = level.Error(logger).Log("msg", "unable to yaml marshal the globalconfig", "err", err)
			continue
		}

		// no need to check err as umarhsall before
		newConfigBytes, _ = yaml.Marshal(cfg)

		if string(oldConfigBytes) != string(newConfigBytes) {
			_ = level.Info(logger).Log("msg", "modified file", "name", configPath)

			err = Setup(logger, customLogger, cfg, version)
			if err != nil {
				_ = level.Error(logger).Log("msg", "ignoring issuer changes because of error", "path", configPath, "err", err)
				metrics.SetConfigError(1)
				continue
			}

			vault.GlobalClient, err = vault.InitClient(cfg.Storage.Vault, customLogger)
			if err != nil {
				_ = level.Error(logger).Log("msg", "ignoring vault changes because of error", "path", configPath, "err", err)
				continue
			}
			config.GlobalConfig = cfg
			metrics.IncConfigReload()
			metrics.SetConfigError(0)
		}
		_ = level.Debug(logger).Log("msg", "check config file changes done")
	}
}

func WatchCertExpiration(logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if isLeaderNow {
			_ = level.Debug(logger).Log("msg", "check certificates expiration")
			err := CheckCertExpiration(AmStore, logger)
			if err != nil {
				_ = level.Error(logger).Log("msg", "Certificate check renewal failed", "err", err)
			}
			_ = level.Debug(logger).Log("msg", "check certificates expiration done")
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
			_ = level.Debug(logger).Log("msg", "check tokens expiration")
			data, err := AmStore.ListAllTokens()
			if err != nil {
				_ = level.Error(logger).Log("err", err)
			}
			for tokenID, tokenData := range data {

				if tokenData.Expires == "Never" {
					continue
				}
				layout := "2006-01-02 15:04:05 -0700 MST"
				t, err := time.Parse(layout, tokenData.Expires)
				if err != nil {
					_ = level.Error(logger).Log("msg", "failed to parse token expiration time", "token_id", tokenID, "err", err)
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
						_ = level.Error(logger).Log("msg", "failed to delete token from vault", "token_id", tokenID, "err", err)
						continue
					}
					err = AmStore.DeleteToken(tokenID)
					if err != nil {
						_ = level.Error(logger).Log("msg", "failed to delete token from ring", "token_id", tokenID, "err", err)
					}
				}
			}
			_ = level.Debug(logger).Log("msg", "check tokens expiration done")
		}
	}
}

// WatchRateLimitCleanup periodically cleans up expired rate limit entries.
// Entries older than the configured rate limit window are deleted to prevent unbounded growth.
func WatchRateLimitCleanup(logger log.Logger, interval time.Duration) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if isLeaderNow {
			_ = level.Debug(logger).Log("msg", "check rate limit cleanup")

			// Skip if rate limiting is not enabled
			if !config.GlobalConfig.Common.RateLimitEnabled {
				_ = level.Debug(logger).Log("msg", "rate limiting disabled, skipping cleanup")
				continue
			}

			// Get the configured window duration
			windowStr := config.GlobalConfig.Common.RateLimitWindow
			if windowStr == "" {
				windowStr = "1h"
			}
			window, err := time.ParseDuration(windowStr)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to parse rate limit window", "err", err)
				continue
			}

			// List all rate limits
			rateLimits, err := AmStore.ListAllRateLimits()
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to list rate limits", "err", err)
				continue
			}

			now := time.Now()
			cleanedCount := 0

			for key, rateLimit := range rateLimits {
				// Check if the window has expired
				windowStart := time.UnixMilli(rateLimit.WindowStartAt)
				windowEnd := windowStart.Add(window)

				if now.After(windowEnd) {
					// Entry expired, delete it
					err := AmStore.DeleteRateLimit(rateLimit.Owner, rateLimit.Issuer, rateLimit.Domain)
					if err != nil {
						_ = level.Error(logger).Log("msg", "failed to delete expired rate limit", "key", key, "err", err)
						continue
					}
					cleanedCount++
				}
			}

			if cleanedCount > 0 {
				_ = level.Info(logger).Log("msg", "cleaned up expired rate limit entries", "count", cleanedCount)
			}
			_ = level.Debug(logger).Log("msg", "check rate limit cleanup done")
		}
	}
}

func WatchIssuerHealth(logger log.Logger, customLogger *logrus.Logger, interval time.Duration, version string) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {

		_ = level.Debug(logger).Log("msg", "check issuer health")
		for issuer, issuerConf := range config.GlobalConfig.Issuer {

			issuerError := 1.0
			privateKeyPath := fmt.Sprintf("%s/%s/private_key.pem", config.GlobalConfig.Common.RootPathAccount, issuer)

			privateKeyBytes, err := os.ReadFile(filepath.Clean(privateKeyPath))
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to read private key file", "issuer", issuer, "path", privateKeyPath, "err", err)
				metrics.SetIssuerConfigError(issuer, issuerError)
				continue
			}
			privateKeyPEM, err := certcrypto.ParsePEMPrivateKey(privateKeyBytes)
			if err != nil {
				_ = level.Error(logger).Log("msg", "unable to parse private key", "issuer", issuer, "path", privateKeyPath, "err", err)
				metrics.SetIssuerConfigError(issuer, issuerError)
				continue
			}

			userAgent := fmt.Sprintf("acme-manager/%s", version)
			_, _, err = tryRecoverRegistration(customLogger, config.GlobalConfig, privateKeyPEM, issuerConf.Contact, issuerConf.CADirURL, userAgent)
			if err != nil {
				_ = level.Error(logger).Log("msg", "unable to recover registration account", "issuer", issuer, "private_key_path", privateKeyPath, "err", err)
			}

			metrics.SetIssuerConfigError(issuer, 0.0)
		}
		_ = level.Debug(logger).Log("msg", "check issuer health done")
	}
}
