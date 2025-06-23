package certstore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/go-acme/lego/v4/lego"

	"github.com/fgouteroux/acme_manager/storage/vault"
)

func Cleanup(logger log.Logger, interval time.Duration, certExpDays int, cleanupCertRevokeLastVersion bool) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		CleanupTokens(logger)
		CleanupCertificateVersions(logger, certExpDays, cleanupCertRevokeLastVersion)
	}
}

func CleanupTokens(logger log.Logger) {
	secrets, err := vault.GlobalClient.ListSecretWithAppRole(vault.GlobalClient.Config.TokenPrefix + "/")
	if err != nil {
		_ = level.Error(logger).Log("msg", "failed to list vault token secrets", "err", err)
		return
	}

	_ = level.Debug(logger).Log("msg", fmt.Sprintf("vault token secrets list: %v", secrets))

	for _, secretPath := range secrets {
		// Retrieve the list of versions for the secret
		versions, err := vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).GetVersionsAsList(context.Background(), secretPath)
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to get vault token versions secret %s", secretPath), "err", err)
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
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to delete inactive vault token secret %s", secretPath), "err", err)
			} else {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("Deleted inactive vault token secret %s", secretPath))
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

	_ = level.Debug(logger).Log("msg", fmt.Sprintf("vault certificate secrets list: %v", secrets))

	for _, secretPath := range secrets {
		// Retrieve the list of versions for the secret
		versions, err := vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).GetVersionsAsList(context.Background(), secretPath)
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to get vault certificate versions secret %s", secretPath), "err", err)
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
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to permanently delete inactive vault certificate secret %s", secretPath), "err", err)
			} else {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("Permanently deleted inactive vault certificate secret %s", secretPath))
			}
			continue
		}

		if !cleanupCertRevokeLastVersion {
			// a secret must contain almost 2 versions
			if len(versions) <= 1 {
				_ = level.Debug(logger).Log("msg", fmt.Sprintf("Skip secret %s containing less than 2 versions", secretPath))
				continue
			}

			// Exclude the latest version (first element) from the list
			versions = versions[1:]
		}

		for _, version := range versions {
			versionNumber := version.Version

			_ = level.Debug(logger).Log("msg", fmt.Sprintf("Checking version %d of secret %s ", versionNumber, secretPath))

			if version.Destroyed {
				_ = level.Debug(logger).Log("msg", fmt.Sprintf("Skip destroyed version %d of secret %s", versionNumber, secretPath))
				continue
			}

			// check if secret has ben deleted
			if !version.DeletionTime.IsZero() {
				// Undelete the version if it is deleted
				err = vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).Undelete(context.Background(), secretPath, []int{versionNumber})
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to undelete version %d of secret %s", versionNumber, secretPath), "err", err)
					continue
				}
				_ = level.Debug(logger).Log("msg", fmt.Sprintf("Undeleted version %d of secret %s", versionNumber, secretPath))

			}

			// Retrieve the specific version of the secret
			secretData, err := vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).GetVersion(context.Background(), secretPath, versionNumber)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to get version %d of secret %s", versionNumber, secretPath), "err", err)
				continue
			}

			data := MapInterfaceToCertMap(secretData.Data)
			if data.Expires == "" {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to get expires date for version %d of secret %s", versionNumber, secretPath))
				continue
			}

			expires, err := time.Parse("2006-01-02 15:04:05 -0700 MST", data.Expires)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to parse expires date for version %d of secret %s", versionNumber, secretPath), "err", err)
				continue
			}

			now := time.Now()
			daysDelay := now.AddDate(0, 0, certExpDays)

			if expires.Before(now) {
				// Destroy the secret version if certificate is expired
				err = vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).Destroy(context.Background(), secretPath, []int{versionNumber})
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to destroy version %d of secret %s", versionNumber, secretPath), "err", err)

					continue
				}
				_ = level.Info(logger).Log("msg", fmt.Sprintf("Destroyed expired certificate version %d of secret %s", versionNumber, secretPath))

			} else if expires.Before(daysDelay) {
				// Revoke the secret if it expires within given days
				var issuerAcmeClient *lego.Client
				var issuerFound bool
				if issuerAcmeClient, issuerFound = AcmeClient[data.Issuer]; !issuerFound {
					fmt.Printf("Could not cleanup certificate domain %s, issuer %s not found", data.Domain, data.Issuer)
					continue
				}

				err = issuerAcmeClient.Certificate.Revoke([]byte(data.Cert))
				if err != nil && !strings.Contains(err.Error(), "urn:ietf:params:acme:error:alreadyRevoked") {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to revoke certificate version %d of secret %s", versionNumber, secretPath), "err", err)
					continue
				}

				_ = level.Info(logger).Log("msg", fmt.Sprintf("Certificate domain %s for %s issuer revoked", data.Domain, data.Issuer))

				// Destroy the secret version if it is expire soon
				err = vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).Destroy(context.Background(), secretPath, []int{versionNumber})
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Failed to destroy expired soon certificate version %d of secret %s", versionNumber, secretPath), "err", err)
					continue
				}
				_ = level.Info(logger).Log("msg", fmt.Sprintf("Destroyed expired soon certificate version %d of secret %s", versionNumber, secretPath))
			}
		}
	}
}
