package certstore

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/cmd"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"

	"gopkg.in/yaml.v3"
)

func OnStartup(logger log.Logger, configPath string, enableAPI bool) error {
	isLeaderNow, err := ring.IsLeader(AmStore.RingConfig)
	if err != nil {
		_ = level.Warn(logger).Log("msg", "Failed to determine the ring leader", "err", err)
		return err
	}

	data, err := AmStore.GetKVRing(AmRingKey)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return err
	}

	if enableAPI {
		tokenData, err := AmStore.GetKVRingToken(TokenRingKey)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			return err
		}
		if len(tokenData) == 0 {
			// udpate kv store
			AmStore.PutKVRing(TokenRingKey, getVaultAllToken(logger))
		}
	}

	if len(data) == 0 {
		if !isLeaderNow {
			_ = level.Debug(logger).Log("msg", "Skipping because this node is not the ring leader")
			return nil
		}

		vaultCertList := getVaultAllCertificate(logger)

		var content []cert.Certificate

		if enableAPI {
			for _, certData := range vaultCertList {
				metrics.IncManagedCertificate(certData.Issuer)
			}
			content = vaultCertList
		} else {
			configBytes, err := os.ReadFile(filepath.Clean(configPath))
			if err != nil {
				return err
			}

			var cfg cert.Config
			err = yaml.Unmarshal(configBytes, &cfg)
			if err != nil {
				return err
			}
			metrics.SetCertificateConfigError(0)

			_ = level.Info(logger).Log("msg", "Checking certificates from config file")

			certConfig = cfg

			for _, certData := range cfg.Certificate {

				idx := slices.IndexFunc(vaultCertList, func(c cert.Certificate) bool {
					return c.Domain == certData.Domain && c.Issuer == certData.Issuer
				})

				if idx >= 0 {
					c := vaultCertList[idx]
					c.Bundle = certData.Bundle
					c.SAN = certData.SAN

					if certData.Days == 0 {
						c.Days = config.GlobalConfig.Common.CertDays
					} else {
						c.Days = certData.Days
					}

					content = append(content, c)
				} else {
					newCert, err := CreateRemoteCertificateResource(certData, logger)
					if err != nil {
						_ = level.Error(logger).Log("err", err)
						os.Exit(1)
					}

					if config.GlobalConfig.Common.CertDeploy {
						CreateLocalCertificateResource(certData.Domain, certData.Issuer, logger)
					}
					content = append(content, newCert)
				}
			}

			certStat := make(map[string]float64)
			for _, certData := range vaultCertList {

				idx := slices.IndexFunc(content, func(c cert.Certificate) bool {
					return c.Domain == certData.Domain && c.Issuer == certData.Issuer
				})

				if idx == -1 {
					if config.GlobalConfig.Common.PruneCertificate {
						_ = level.Info(logger).Log("msg", fmt.Sprintf("Removing certificate '%s' present in vault but not in config file", certData.Domain))
						// Clean certificate in vault but not in config file
						err := DeleteRemoteCertificateResource(certData.Domain, certData.Issuer, logger)
						if err != nil {
							_ = level.Error(logger).Log("err", err)
							os.Exit(1)
						}
						if config.GlobalConfig.Common.CertDeploy {
							DeleteLocalCertificateResource(certData.Domain, certData.Issuer, logger)
						}
					} else {
						_ = level.Info(logger).Log("msg", fmt.Sprintf("(noop) - removing certificate '%s' present in vault but not in config file", certData.Domain))
					}
				} else {
					certStat[certData.Issuer] += 1.0
				}
			}

			for issuer, count := range certStat {
				metrics.SetManagedCertificate(issuer, count)
			}

			// update local cache with kv store value
			localCache.Set(AmRingKey, content)

			if config.GlobalConfig.Common.CmdEnabled {
				cmd.Execute(logger, config.GlobalConfig.Common)
			}
		}

		// udpate kv store
		AmStore.PutKVRing(AmRingKey, content)

	} else {
		_ = level.Info(logger).Log("msg", "Processing certificates as simple peer")

		if !enableAPI {
			// update local cache with kv store value
			localCache.Set(AmRingKey, data)

			err := CheckAndDeployLocalCertificate(AmStore, logger)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
			}
		}
	}
	return nil
}

func getVaultAllCertificate(logger log.Logger) []cert.Certificate {
	_ = level.Info(logger).Log("msg", "Retrieving certificates from vault")

	vaultSecrets, err := vault.GlobalClient.ListSecretWithAppRole(config.GlobalConfig.Storage.Vault.CertPrefix + "/")

	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	var vaultCertList []cert.Certificate
	if len(vaultSecrets) > 0 {

		var vaultCertCount int
		for _, secretKey := range vaultSecrets {
			secretKeyPath := config.GlobalConfig.Storage.Vault.CertPrefix + "/" + secretKey

			secretKeyPathArr := strings.Split(secretKeyPath, "/")
			issuer := secretKeyPathArr[len(secretKeyPathArr)-2]
			name := secretKeyPathArr[len(secretKeyPathArr)-1]

			tmp := cert.Certificate{
				Domain: name,
				Issuer: issuer,
			}

			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			var vaultCertBytes, vaultKeyBytes []byte
			if cert, ok := secret["cert"]; ok {
				vaultCertBytes = []byte(cert.(string))
			} else {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("No certificate found in vault secret key %s", secretKeyPath))
				continue
			}

			if key, ok := secret["key"]; ok {
				vaultKeyBytes = []byte(key.(string))
			} else {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("No private key found in vault secret key %s", secretKeyPath))
				continue
			}

			if owner, ok := secret["owner"]; ok {
				tmp.Owner = owner.(string)
			}

			vaultCert, err := kvStore(tmp, vaultCertBytes, vaultKeyBytes)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
			}

			var certBytes, keyBytes []byte
			certFilePath := config.GlobalConfig.Common.CertDir + secretKey + ".crt"

			if utils.FileExists(certFilePath) {
				certBytes, err = os.ReadFile(filepath.Clean(certFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err)
				}
			}

			keyFilePath := config.GlobalConfig.Common.CertDir + secretKey + ".key"
			err = utils.CreateNonExistingFolder(filepath.Dir(keyFilePath), config.GlobalConfig.Common.CertDirPerm)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}
			if utils.FileExists(keyFilePath) {
				keyBytes, err = os.ReadFile(filepath.Clean(keyFilePath))
				if err != nil {
					_ = level.Error(logger).Log("err", err)
				}
			}

			if config.GlobalConfig.Common.CertDeploy {
				currentCert, err := kvStore(tmp, certBytes, keyBytes)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
				}

				if currentCert.Fingerprint != vaultCert.Fingerprint {
					err := os.WriteFile(certFilePath, vaultCertBytes, config.GlobalConfig.Common.CertFilePerm)
					if err != nil {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save certificate file %s", certFilePath), "err", err)
					}
				}

				if currentCert.KeyFingerprint != vaultCert.KeyFingerprint {
					err := os.WriteFile(keyFilePath, vaultKeyBytes, config.GlobalConfig.Common.CertKeyFilePerm)
					if err != nil {
						_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to save private key file %s", keyFilePath), "err", err)
					}
				}
			}

			vaultCertList = append(vaultCertList, vaultCert)
			vaultCertCount++

		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Found %d certificates from vault", vaultCertCount))
	} else {
		_ = level.Warn(logger).Log("msg", "No certificates found from vault")
	}
	return vaultCertList
}

func getVaultAllToken(logger log.Logger) map[string]Token {
	_ = level.Info(logger).Log("msg", "Retrieving tokens from vault")

	vaultSecrets, err := vault.GlobalClient.ListSecretWithAppRole(
		config.GlobalConfig.Storage.Vault.TokenPrefix + "/",
	)

	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	tokenMap := make(map[string]Token)
	if len(vaultSecrets) > 0 {

		var vaultTokenCount int
		for _, secretKey := range vaultSecrets {
			secretKeyPath := config.GlobalConfig.Storage.Vault.TokenPrefix + "/" + secretKey

			secretKeyPathArr := strings.Split(secretKeyPath, "/")
			username := secretKeyPathArr[len(secretKeyPathArr)-2]
			ID := secretKeyPathArr[len(secretKeyPathArr)-1]

			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			var scope []string
			if secret["scope"] != nil {
				for _, item := range secret["scope"].([]interface{}) {
					scope = append(scope, item.(string))
				}

				tokenMap[ID] = Token{Hash: secret["tokenHash"].(string), Scope: scope, Username: username, Expires: secret["expires"].(string)}
				vaultTokenCount++
			}
		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Found %d tokens from vault", vaultTokenCount))
	} else {
		_ = level.Warn(logger).Log("msg", "No tokens found from vault")
	}
	return tokenMap
}
