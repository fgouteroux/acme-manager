package certstore

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
)

func OnStartup(logger log.Logger) error {
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

	tokenData, err := AmStore.GetKVRingToken(TokenRingKey)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return err
	}
	if len(tokenData) == 0 {
		// udpate kv store
		AmStore.PutKVRing(TokenRingKey, getVaultAllToken(logger))
	}

	if len(data) == 0 {
		if !isLeaderNow {
			_ = level.Debug(logger).Log("msg", "Skipping because this node is not the ring leader")
			return nil
		}

		vaultCertList := getVaultAllCertificate(logger)

		var content []Certificate
		for _, certData := range vaultCertList {
			metrics.IncManagedCertificate(certData.Issuer, certData.Owner)
		}
		content = vaultCertList

		// udpate kv store
		AmStore.PutKVRing(AmRingKey, content)
	}
	return nil
}

func getVaultAllCertificate(logger log.Logger) []Certificate {
	_ = level.Info(logger).Log("msg", "Retrieving certificates from vault")

	vaultSecrets, err := vault.GlobalClient.ListSecretWithAppRole(config.GlobalConfig.Storage.Vault.CertPrefix + "/")

	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	var vaultCertList []Certificate
	if len(vaultSecrets) > 0 {

		var vaultCertCount int
		for _, secretKey := range vaultSecrets {
			secretKeyPath := config.GlobalConfig.Storage.Vault.CertPrefix + "/" + secretKey
			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			if _, ok := secret["cert"]; !ok {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("No certificate found in vault secret key %s", secretKeyPath))
				continue
			}

			cert, err := json.Marshal(secret)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			var vaultCert Certificate
			err = json.Unmarshal(cert, &vaultCert)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
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
			ID := secretKeyPathArr[len(secretKeyPathArr)-1]

			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			val, err := json.Marshal(secret)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			var token Token
			err = json.Unmarshal(val, &token)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			tokenMap[ID] = token
			vaultTokenCount++

		}
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Found %d tokens from vault", vaultTokenCount))
	} else {
		_ = level.Warn(logger).Log("msg", "No tokens found from vault")
	}
	return tokenMap
}
