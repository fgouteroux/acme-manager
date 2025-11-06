package certstore

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/fgouteroux/acme-manager/config"
	"github.com/fgouteroux/acme-manager/metrics"
	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/ring"
	"github.com/fgouteroux/acme-manager/storage/vault"
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
		_ = level.Error(logger).Log("msg", "failed to list certificates from KV ring", "err", err)
		return err
	}

	if len(certificateData) == 0 && isLeaderNow {
		// if leader and no data exists, populate from vault
		_ = level.Info(logger).Log("msg", "leader node with empty certificate data, populating from vault")
		vaultCertList, err := getVaultAllCertificate(logger)
		if err != nil {
			_ = level.Error(logger).Log("msg", "failed to get certificates from vault", "err", err)
			os.Exit(1)
		}

		// Store each certificate with its own key
		for _, certData := range vaultCertList {
			err := AmStore.PutCertificate(certData)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to store certificate",
					"domain", certData.Domain, "issuer", certData.Issuer, "owner", certData.Owner, "err", err)
				continue
			}
			metrics.IncManagedCertificate(certData.Issuer, certData.Owner)
		}
	} else if len(certificateData) > 0 {
		_ = level.Info(logger).Log("msg", "found existing certificates in KV ring", "count", len(certificateData))
	}

	// Handle tokens
	tokenData, err := AmStore.ListAllTokens()
	if err != nil {
		_ = level.Error(logger).Log("msg", "failed to get token data from KV ring", "err", err)
		return err
	}

	if len(tokenData) == 0 && isLeaderNow {
		// if leader and no data exists, populate from vault
		_ = level.Info(logger).Log("msg", "leader node with empty token data, populating from vault")
		tokens, err := getVaultAllToken(logger)
		if err != nil {
			_ = level.Error(logger).Log("msg", "failed to get tokens from vault", "err", err)
			os.Exit(1)
		}

		// Store in ring
		for tokenID, token := range tokens {
			fmt.Println(tokenID)

			existing, err := AmStore.GetToken(tokenID)
			if err != nil && !strings.Contains(err.Error(), "not found") {
				_ = level.Error(logger).Log("msg", "failed to check token existence",
					"token_id", tokenID, "err", err)
				continue
			}

			if existing != nil {
				_ = level.Debug(logger).Log("msg", "token already exists, skipping", "token_id", tokenID)
				continue
			}

			err = AmStore.PutToken(tokenID, token)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to store token",
					"token_id", tokenID, "owner", token.Username, "err", err)
				continue
			}
		}
	} else if len(tokenData) > 0 {
		_ = level.Info(logger).Log("msg", "found existing tokens in KV ring", "count", len(tokenData))
	}

	// Handle challenges
	challengeData, err := AmStore.ListAllChallenges()
	if err != nil {
		_ = level.Error(logger).Log("msg", "failed to get challenge data from KV ring", "err", err)
		return err
	}

	if len(challengeData) > 0 {
		_ = level.Info(logger).Log("msg", "found existing challenges in KV ring", "count", len(challengeData))
	}

	return nil
}

func getVaultAllCertificate(logger log.Logger) ([]*models.Certificate, error) {
	_ = level.Info(logger).Log("msg", "retrieving certificates from vault")

	var vaultCertList []*models.Certificate
	vaultSecrets, err := vault.GlobalClient.ListSecretWithAppRole(config.GlobalConfig.Storage.Vault.CertPrefix + "/")
	if err != nil {
		return vaultCertList, err
	}
	_ = level.Debug(logger).Log("msg", "vault certificate secrets listed", "count", len(vaultSecrets))

	if len(vaultSecrets) > 0 {

		var vaultCertCount int
		for _, secretKeyPath := range vaultSecrets {
			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to get secret from vault", "secret_path", secretKeyPath, "err", err)
				continue
			}

			if _, ok := secret["cert"]; !ok {
				_ = level.Debug(logger).Log("msg", "no certificate found in vault secret", "secret_path", secretKeyPath)
				continue
			}

			cert, err := json.Marshal(secret)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to marshal certificate", "err", err)
				continue
			}

			var vaultCert *models.Certificate
			err = json.Unmarshal(cert, &vaultCert)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to unmarshal certificate", "err", err)
				continue
			}

			vaultCertList = append(vaultCertList, vaultCert)
			vaultCertCount++

		}
		_ = level.Info(logger).Log("msg", "found certificates from vault", "count", vaultCertCount)
	} else {
		_ = level.Warn(logger).Log("msg", "no certificates found from vault")
	}
	return vaultCertList, nil
}

func getVaultAllToken(logger log.Logger) (map[string]*models.Token, error) {
	_ = level.Info(logger).Log("msg", "retrieving tokens from vault")

	tokenMap := make(map[string]*models.Token)
	vaultSecrets, err := vault.GlobalClient.ListSecretWithAppRole(
		config.GlobalConfig.Storage.Vault.TokenPrefix + "/",
	)
	if err != nil {
		return tokenMap, err
	}
	_ = level.Debug(logger).Log("msg", "vault token secrets listed", "count", len(vaultSecrets))

	if len(vaultSecrets) > 0 {

		var vaultTokenCount int
		for _, secretKeyPath := range vaultSecrets {
			secretKeyPathArr := strings.Split(secretKeyPath, "/")
			ID := secretKeyPathArr[len(secretKeyPathArr)-1]

			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to get secret from vault", "secret_path", secretKeyPath, "err", err)
				continue
			}

			if _, ok := secret["tokenHash"]; !ok {
				_ = level.Debug(logger).Log("msg", "no token found in vault secret", "secret_path", secretKeyPath)
				continue
			}

			val, err := json.Marshal(secret)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to marshal token", "err", err)
				continue
			}

			var token *models.Token
			err = json.Unmarshal(val, &token)
			if err != nil {
				_ = level.Error(logger).Log("msg", "failed to unmarshal token", "err", err)
				continue
			}

			tokenMap[ID] = token
			vaultTokenCount++

		}
		_ = level.Info(logger).Log("msg", "found tokens from vault", "count", vaultTokenCount)
	} else {
		_ = level.Warn(logger).Log("msg", "no tokens found from vault")
	}
	return tokenMap, nil
}
