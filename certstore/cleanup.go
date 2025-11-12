package certstore

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/go-acme/lego/v4/lego"

	"github.com/fgouteroux/acme-manager/ring"
	"github.com/fgouteroux/acme-manager/storage/vault"
)

func Cleanup(logger log.Logger, interval time.Duration, certExpDays int, cleanupCertRevokeLastVersion bool) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)
		if isLeaderNow {
			CleanupTokens(logger)
			CleanupCertificateVersions(logger, certExpDays, cleanupCertRevokeLastVersion)
		}
	}
}

func CleanupTokens(logger log.Logger) {
	secrets, err := vault.GlobalClient.ListSecretWithAppRole(vault.GlobalClient.Config.TokenPrefix + "/")
	if err != nil {
		_ = level.Error(logger).Log("msg", "failed to list vault token secrets", "err", err)
		return
	}

	_ = level.Debug(logger).Log("msg", "vault token secrets listed", "count", len(secrets))

	for _, secretPath := range secrets {
		// Retrieve the list of versions for the secret
		versions, err := vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).GetVersionsAsList(context.Background(), secretPath)
		if err != nil {
			_ = level.Error(logger).Log("msg", "failed to get vault token versions", "secret_path", secretPath, "err", err)
			continue
		}

		// Sort the versions by version number in descending order
		sort.Slice(versions, func(i, j int) bool {
			return versions[i].Version > versions[j].Version
		})

		var inactiveSecret bool
		if !versions[0].DeletionTime.IsZero() {
			inactiveSecret = true
		}

		if inactiveSecret {
			err := vault.GlobalClient.DeleteSecretMetadataWithAppRole(secretPath)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to delete inactive vault token secret", "secret_path", secretPath, "err", err)
			} else {
				_ = level.Info(logger).Log("msg", "deleted inactive vault token secret", "secret_path", secretPath)
			}
			continue
		}
	}
}

func CleanupCertificateVersions(logger log.Logger, certExpDays int, cleanupCertRevokeLastVersion bool) {
	secrets, err := vault.GlobalClient.ListSecretWithAppRole(vault.GlobalClient.Config.CertPrefix + "/")
	if err != nil {
		_ = level.Error(logger).Log("msg", "failed to list vault certificate secrets", "err", err)
		return
	}

	_ = level.Debug(logger).Log("msg", "vault certificate secrets listed", "count", len(secrets))

	for _, secretPath := range secrets {
		// Retrieve the list of versions for the secret
		versions, err := vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).GetVersionsAsList(context.Background(), secretPath)
		if err != nil {
			_ = level.Error(logger).Log("msg", "failed to get vault certificate versions", "secret_path", secretPath, "err", err)
			continue
		}

		// Sort the versions by version number in descending order
		sort.Slice(versions, func(i, j int) bool {
			return versions[i].Version > versions[j].Version
		})

		// if all versions are destroyed, permanently delete secret
		inactiveSecret := true
		for _, version := range versions {
			if !version.Destroyed {
				inactiveSecret = false
			}
		}

		if inactiveSecret {
			err := vault.GlobalClient.DeleteSecretMetadataWithAppRole(secretPath)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to permanently delete inactive vault certificate secret", "secret_path", secretPath, "err", err)
			} else {
				_ = level.Info(logger).Log("msg", "permanently deleted inactive vault certificate secret", "secret_path", secretPath)
			}
			continue
		}

		if !cleanupCertRevokeLastVersion {
			// a secret must contain almost 2 versions
			if len(versions) <= 1 {
				_ = level.Debug(logger).Log("msg", "skipping secret containing less than 2 versions", "secret_path", secretPath)
				continue
			}

			// Exclude the latest version (first element) from the list
			versions = versions[1:]
		}

		for _, version := range versions {
			versionNumber := version.Version

			_ = level.Debug(logger).Log("msg", "checking version of secret", "version", versionNumber, "secret_path", secretPath)

			if version.Destroyed {
				_ = level.Debug(logger).Log("msg", "skipping destroyed version", "version", versionNumber, "secret_path", secretPath)
				continue
			}

			// check if secret has ben deleted
			if !version.DeletionTime.IsZero() {
				// Undelete the version if it is deleted
				err = vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).Undelete(context.Background(), secretPath, []int{versionNumber})
				if err != nil {
					_ = level.Error(logger).Log("msg", "failed to undelete version", "version", versionNumber, "secret_path", secretPath, "err", err)
					continue
				}
				_ = level.Debug(logger).Log("msg", "undeleted version", "version", versionNumber, "secret_path", secretPath)

			}

			// Retrieve the specific version of the secret
			secretData, err := vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).GetVersion(context.Background(), secretPath, versionNumber)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to get version of secret", "version", versionNumber, "secret_path", secretPath, "err", err)
				continue
			}

			data := MapInterfaceToCertMap(secretData.Data)
			if data.Expires == "" {
				_ = level.Error(logger).Log("msg", "failed to get expires date for version", "version", versionNumber, "secret_path", secretPath)
				continue
			}

			expires, err := time.Parse("2006-01-02 15:04:05 -0700 MST", data.Expires)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to parse expires date", "version", versionNumber, "secret_path", secretPath, "err", err)
				continue
			}

			now := time.Now()
			daysDelay := now.AddDate(0, 0, certExpDays)

			if expires.Before(now) {
				// Destroy the secret version if certificate is expired
				err = vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).Destroy(context.Background(), secretPath, []int{versionNumber})
				if err != nil {
					_ = level.Error(logger).Log("msg", "failed to destroy version", "version", versionNumber, "secret_path", secretPath, "err", err)

					continue
				}
				_ = level.Info(logger).Log("msg", "destroyed expired certificate version", "version", versionNumber, "secret_path", secretPath)

			} else if expires.Before(daysDelay) {
				// Revoke the secret if it expires within given days
				var issuerAcmeClient *lego.Client
				var issuerFound bool
				if issuerAcmeClient, issuerFound = AcmeClient[data.Issuer]; !issuerFound {
					fmt.Printf("Could not cleanup certificate domain %s, issuer %s not found", data.Domain, data.Issuer)
					continue
				}

				err = RevokeCertificateWithVerification(logger, issuerAcmeClient, []byte(data.Cert), data.Issuer, data.Owner, data.Domain, &versionNumber)
				if err != nil {
					_ = level.Error(logger).Log("msg", "skipping destruction due to revocation failure", "version", versionNumber, "secret_path", secretPath)
					continue
				}

				// Destroy the secret version if it is expire soon
				err = vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).Destroy(context.Background(), secretPath, []int{versionNumber})
				if err != nil {
					_ = level.Error(logger).Log("msg", "failed to destroy expired soon certificate version", "version", versionNumber, "secret_path", secretPath, "err", err)
					continue
				}
				_ = level.Info(logger).Log("msg", "destroyed expired soon certificate version", "version", versionNumber, "secret_path", secretPath)
			}
		}
	}
}
