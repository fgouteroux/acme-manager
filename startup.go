package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/cmd"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"

	"gopkg.in/yaml.v3"
)

func onStartup(amStore *CertStore, logger log.Logger, configPath string) error {
	isLeaderNow, err := ring.IsLeader(amStore.RingConfig)
	if err != nil {
		level.Warn(logger).Log("msg", "Failed to determine the ring leader", "err", err) // #nosec G104
		return err
	}

	data, err := amStore.GetKVRing()
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		return err
	}

	configBytes, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return err
	}

	var cfg cert.Config
	err = yaml.Unmarshal(configBytes, &cfg)
	if err != nil {
		return err
	}

	certConfig = cfg

	if len(data) == 0 {
		if !isLeaderNow {
			level.Debug(logger).Log("msg", "Skipping because this node is not the ring leader") // #nosec G104
			return nil
		}

		level.Info(logger).Log("msg", "Retrieving certificates from vault") // #nosec G104

		vaultSecrets, err := vault.ListSecretWithAppRole(
			vaultClient,
			globalConfig.Storage.Vault,
			globalConfig.Storage.Vault.SecretPrefix+"/",
		)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			os.Exit(1)
		}

		var vaultCertList []cert.Certificate
		if len(vaultSecrets) > 0 {

			var vaultCertCount int
			for _, secretKey := range vaultSecrets {
				secretKeyPath := globalConfig.Storage.Vault.SecretPrefix + "/" + secretKey

				secretKeyPathArr := strings.Split(secretKeyPath, "/")
				issuer := secretKeyPathArr[1]
				name := secretKeyPathArr[2]

				tmp := cert.Certificate{
					Domain: name,
					Issuer: issuer,
				}

				secret, err := vault.GetSecretWithAppRole(vaultClient, globalConfig.Storage.Vault, secretKeyPath)
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
					continue
				}

				var vaultCertBytes, vaultKeyBytes []byte
				if cert64, ok := secret["cert"]; ok {
					vaultCertBytes, _ = base64.StdEncoding.DecodeString(cert64.(string))
				} else {
					level.Error(logger).Log("msg", fmt.Sprintf("No certificate found in vault secret key %s", secretKeyPath)) // #nosec G104
					continue
				}

				if key64, ok := secret["key"]; ok {
					vaultKeyBytes, _ = base64.StdEncoding.DecodeString(key64.(string))
				} else {
					level.Error(logger).Log("msg", fmt.Sprintf("No private key found in vault secret key %s", secretKeyPath)) // #nosec G104
					continue
				}

				vaultCert, err := kvStore(tmp, vaultCertBytes, vaultKeyBytes)
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
				}

				var certBytes, keyBytes []byte
				certFilePath := globalConfig.Common.CertDir + secretKey + ".crt"

				if utils.FileExists(certFilePath) {
					certBytes, err = os.ReadFile(filepath.Clean(certFilePath))
					if err != nil {
						level.Error(logger).Log("err", err) // #nosec G104
					}
				}

				keyFilePath := globalConfig.Common.CertDir + secretKey + ".key"
				err = utils.CreateNonExistingFolder(filepath.Dir(keyFilePath))
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
					continue
				}
				if utils.FileExists(keyFilePath) {
					keyBytes, err = os.ReadFile(filepath.Clean(keyFilePath))
					if err != nil {
						level.Error(logger).Log("err", err) // #nosec G104
					}
				}

				if globalConfig.Common.CertDeploy {
					currentCert, err := kvStore(tmp, certBytes, keyBytes)
					if err != nil {
						level.Error(logger).Log("err", err) // #nosec G104
					}

					if currentCert.Fingerprint != vaultCert.Fingerprint {
						err := os.WriteFile(certFilePath, vaultCertBytes, 0600)
						if err != nil {
							level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err) // #nosec G104
						}
					}

					if currentCert.KeyFingerprint != vaultCert.KeyFingerprint {
						err := os.WriteFile(keyFilePath, vaultKeyBytes, 0600)
						if err != nil {
							level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err) // #nosec G104
						}
					}
				}

				vaultCertList = append(vaultCertList, vaultCert)
				vaultCertCount++

			}
			level.Info(logger).Log("msg", fmt.Sprintf("Found %d certificates from vault", vaultCertCount)) // #nosec G104
		}

		level.Info(logger).Log("msg", "Checking certificates from config file") // #nosec G104

		var content []cert.Certificate
		for _, certData := range cfg.Certificate {

			idx := slices.IndexFunc(vaultCertList, func(c cert.Certificate) bool {
				return c.Domain == certData.Domain && c.Issuer == certData.Issuer
			})

			if idx >= 0 {
				c := vaultCertList[idx]
				c.Bundle = certData.Bundle
				c.SAN = certData.SAN

				if certData.Days == 0 {
					c.Days = *certDays
				} else {
					c.Days = certData.Days
				}

				content = append(content, c)
			} else {
				newCert, err := createRemoteCertificateResource(certData, logger)
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
					os.Exit(1)
				}

				if globalConfig.Common.CertDeploy {
					createlocalCertificateResource(certData.Domain, certData.Issuer, logger)
				}
				content = append(content, newCert)
			}
		}

		for _, certData := range vaultCertList {

			idx := slices.IndexFunc(content, func(c cert.Certificate) bool {
				return c.Domain == certData.Domain && c.Issuer == certData.Issuer
			})

			if idx == -1 {
				if globalConfig.Common.PruneCertificate {
					level.Info(logger).Log("msg", fmt.Sprintf("Removing certificate '%s' present in vault but not in config file", certData.Domain)) // #nosec G104
					// Clean certificate in vault but not in config file
					err := deleteRemoteCertificateResource(certData.Domain, certData.Issuer, logger)
					if err != nil {
						level.Error(logger).Log("err", err) // #nosec G104
						os.Exit(1)
					}
					if globalConfig.Common.CertDeploy {
						deletelocalCertificateResource(certData.Domain, certData.Issuer, logger)
					}
				} else {
					level.Info(logger).Log("msg", fmt.Sprintf("(noop) - removing certificate '%s' present in vault but not in config file", certData.Domain)) // #nosec G104
				}
			}
		}

		// udpate kv store
		amStore.PutKVRing(content)

		// update local cache with kv store value
		localCache.Set(amRingKey, content)

		if globalConfig.Common.CmdEnabled {
			cmd.Execute(logger, globalConfig)
		}
	} else {
		level.Info(logger).Log("msg", "Processing certificates as simple peer") // #nosec G104

		// update local cache with kv store value
		localCache.Set(amRingKey, data)

		// not deploy certs
		if globalConfig.Common.CertDeploy {
			return nil
		}

		var hasChange bool
		for _, certData := range data {

			certFilePath := globalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".crt"
			keyFilePath := globalConfig.Common.CertDir + certData.Issuer + "/" + certData.Domain + ".key"

			var certBytes, keyBytes []byte
			if utils.FileExists(certFilePath) {
				certBytes, err = os.ReadFile(filepath.Clean(certFilePath))
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
				}
			}

			if utils.FileExists(keyFilePath) {
				keyBytes, err = os.ReadFile(filepath.Clean(keyFilePath))
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
				}
			}

			currentCert, err := kvStore(certData, certBytes, keyBytes)
			if err != nil {
				level.Error(logger).Log("err", err) // #nosec G104
			}

			var secret map[string]interface{}
			if currentCert.Fingerprint != certData.Fingerprint {
				hasChange = true
				secretKeyPath := globalConfig.Storage.Vault.SecretPrefix + "/" + certData.Issuer + "/" + certData.Domain
				secret, err = vault.GetSecretWithAppRole(vaultClient, globalConfig.Storage.Vault, secretKeyPath)
				if err != nil {
					level.Error(logger).Log("err", err) // #nosec G104
					continue
				}

				if cert64, ok := secret["cert"]; ok {
					certBytes, _ := base64.StdEncoding.DecodeString(cert64.(string))

					err := os.WriteFile(certFilePath, certBytes, 0600)
					if err != nil {
						level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err) // #nosec G104
					}
				} else {
					level.Error(logger).Log("msg", fmt.Sprintf("No certificate found in vault secret key %s", secretKeyPath), "err", err) // #nosec G104
				}
			}

			if currentCert.KeyFingerprint != certData.KeyFingerprint {
				hasChange = true
				secretKeyPath := globalConfig.Storage.Vault.SecretPrefix + "/" + certData.Issuer + "/" + certData.Domain
				if secret == nil {
					secret, err = vault.GetSecretWithAppRole(vaultClient, globalConfig.Storage.Vault, secretKeyPath)
					if err != nil {
						level.Error(logger).Log("err", err) // #nosec G104
						continue
					}
				}
				if key64, ok := secret["key"]; ok {
					keyBytes, _ := base64.StdEncoding.DecodeString(key64.(string))

					err := os.WriteFile(keyFilePath, keyBytes, 0600)
					if err != nil {
						level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err) // #nosec G104
					}
				} else {
					level.Error(logger).Log("msg", fmt.Sprintf("No private key found in vault secret key %s", secretKeyPath), "err", err) // #nosec G104
				}
			}
		}
		if hasChange && globalConfig.Common.CmdEnabled {
			cmd.Execute(logger, globalConfig)
		}
	}
	return nil
}
