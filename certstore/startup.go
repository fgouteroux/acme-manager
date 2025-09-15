package certstore

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/models"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
)

func OnStartup(logger log.Logger) error {
	_ = prometheus.Register(NewCertificateCollector(logger))
	_ = prometheus.Register(NewNodeCollector(logger))

	isLeaderNow, err := ring.IsLeader(AmStore.RingConfig)
	if err != nil {
		_ = level.Warn(logger).Log("msg", "Failed to determine the ring leader", "err", err)
		return err
	}

	// Handle certificates
	certificateData, err := AmStore.ListAllCertificates()
	if err != nil {
		_ = level.Error(logger).Log("msg", "Failed to list certificates from KV ring", "err", err)
		return err
	}

	if len(certificateData) == 0 && isLeaderNow {
		// if leader and no data exists, populate from vault
		_ = level.Info(logger).Log("msg", "Leader node with empty certificate data, populating from vault")
		vaultCertList, err := getVaultAllCertificate(logger)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			os.Exit(1)
		}

		// Store each certificate with its own key
		for _, certData := range vaultCertList {
			err := AmStore.PutCertificate(certData)
			if err != nil {
				_ = level.Error(logger).Log("msg", "Failed to store certificate",
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", certData.Owner, "err", err)
				continue
			}
			metrics.IncManagedCertificate(certData.Issuer, certData.Owner)
		}
	} else if len(certificateData) > 0 {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Found %d existing certificates in KV ring", len(certificateData)))
	}

	// Handle tokens
	tokenData, err := AmStore.ListAllTokens()
	if err != nil {
		_ = level.Error(logger).Log("msg", "Failed to get token data from KV ring", "err", err)
		return err
	}

	if len(tokenData) == 0 && isLeaderNow {
		// if leader and no data exists, populate from vault
		_ = level.Info(logger).Log("msg", "Leader node with empty token data, populating from vault")
		tokens, err := getVaultAllToken(logger)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			os.Exit(1)
		}

		// Store in ring
		for tokenID, token := range tokens {
			fmt.Println(tokenID)

			existing, err := AmStore.GetToken(tokenID)
			if err != nil && !strings.Contains(err.Error(), "not found") {
				_ = level.Error(logger).Log("msg", "Failed to check token existence",
					"tokenID", tokenID, "err", err)
				continue
			}

			if existing != nil {
				_ = level.Debug(logger).Log("msg", "Token already exists, skipping", "tokenID", tokenID)
				continue
			}

			err = AmStore.PutToken(tokenID, token)
			if err != nil {
				_ = level.Error(logger).Log("msg", "Failed to store token",
					"tokenID", tokenID, "owner", token.Username, "err", err)
				continue
			}
		}
	} else if len(tokenData) > 0 {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Found %d existing tokens in KV ring", len(tokenData)))
	}

	// Handle challenges
	challengeData, err := AmStore.ListAllChallenges()
	if err != nil {
		_ = level.Error(logger).Log("msg", "Failed to get challenge data from KV ring", "err", err)
		return err
	}

	if len(challengeData) > 0 {
		_ = level.Info(logger).Log("msg", fmt.Sprintf("Found %d existing challenges in KV ring", len(challengeData)))
	}

	return nil
}

func getVaultAllCertificate(logger log.Logger) ([]*models.Certificate, error) {
	_ = level.Info(logger).Log("msg", "Retrieving certificates from vault")

	var vaultCertList []*models.Certificate
	vaultSecrets, err := vault.GlobalClient.ListSecretWithAppRole(config.GlobalConfig.Storage.Vault.CertPrefix + "/")
	if err != nil {
		return vaultCertList, err
	}
	_ = level.Debug(logger).Log("msg", fmt.Sprintf("vault certificate secrets list: %v", vaultSecrets))

	if len(vaultSecrets) > 0 {

		var vaultCertCount int
		for _, secretKeyPath := range vaultSecrets {
			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			if _, ok := secret["cert"]; !ok {
				_ = level.Debug(logger).Log("msg", fmt.Sprintf("No certificate found in vault secret key %s", secretKeyPath))
				continue
			}

			cert, err := json.Marshal(secret)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			var vaultCert *models.Certificate
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
	return vaultCertList, nil
}

func getVaultAllToken(logger log.Logger) (map[string]*models.Token, error) {
	_ = level.Info(logger).Log("msg", "Retrieving tokens from vault")

	tokenMap := make(map[string]*models.Token)
	vaultSecrets, err := vault.GlobalClient.ListSecretWithAppRole(
		config.GlobalConfig.Storage.Vault.TokenPrefix + "/",
	)
	if err != nil {
		return tokenMap, err
	}
	_ = level.Debug(logger).Log("msg", fmt.Sprintf("vault token secrets list: %v", vaultSecrets))

	if len(vaultSecrets) > 0 {

		var vaultTokenCount int
		for _, secretKeyPath := range vaultSecrets {
			secretKeyPathArr := strings.Split(secretKeyPath, "/")
			ID := secretKeyPathArr[len(secretKeyPathArr)-1]

			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			if _, ok := secret["tokenHash"]; !ok {
				_ = level.Debug(logger).Log("msg", fmt.Sprintf("No token found in vault secret key %s", secretKeyPath))
				continue
			}

			val, err := json.Marshal(secret)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			var token *models.Token
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
	return tokenMap, nil
}
