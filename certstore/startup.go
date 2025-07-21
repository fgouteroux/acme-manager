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
	"github.com/fgouteroux/acme_manager/queue"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
)

var (
	CertificateQueue *queue.Queue
	ChallengeQueue   *queue.Queue
	TokenQueue       *queue.Queue
)

func OnStartup(logger log.Logger) error {
	_ = prometheus.Register(NewCertificateCollector(logger))

	// init queues
	CertificateQueue = queue.NewQueue("certificate")
	ChallengeQueue = queue.NewQueue("challenge")
	TokenQueue = queue.NewQueue("token")

	// init workers
	tokenWorker := queue.NewWorker(TokenQueue, logger)
	challengeWorker := queue.NewWorker(ChallengeQueue, logger)
	certificateWorker := queue.NewWorker(CertificateQueue, logger)

	// start workers
	go tokenWorker.DoWork()
	go certificateWorker.DoWork()
	go challengeWorker.DoWork()

	// init local cache
	localCache.Set(AmCertificateRingKey, "")
	localCache.Set(AmTokenRingKey, "")
	localCache.Set(AmChallengeRingKey, "")

	isLeaderNow, err := ring.IsLeader(AmStore.RingConfig)
	if err != nil {
		_ = level.Warn(logger).Log("msg", "Failed to determine the ring leader", "err", err)
		return err
	}

	certificateData, err := AmStore.GetKVRing(AmCertificateRingKey, isLeaderNow)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return err
	}

	tokenData, err := AmStore.GetKVRingToken(AmTokenRingKey, isLeaderNow)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		return err
	}

	challengeData, err := AmStore.GetKVRingMapString(AmChallengeRingKey, isLeaderNow)
	if err != nil {
		return err
	}
	if challengeData != nil {
		// update local cache
		content, _ := json.Marshal(challengeData)
		localCache.Set(AmChallengeRingKey, string(content))
	}

	if len(tokenData) == 0 && isLeaderNow {
		tokens := getVaultAllToken(logger)

		// update local cache
		content, _ := json.Marshal(tokens)
		localCache.Set(AmTokenRingKey, content)

		// udpate kv store
		AmStore.PutKVRing(AmTokenRingKey, tokens)
	} else {
		// update local cache
		content, _ := json.Marshal(tokenData)
		localCache.Set(AmTokenRingKey, string(content))
	}

	if len(certificateData) == 0 && isLeaderNow {

		vaultCertList := getVaultAllCertificate(logger)

		var content []Certificate
		for _, certData := range vaultCertList {
			metrics.IncManagedCertificate(certData.Issuer, certData.Owner)
		}
		content = vaultCertList

		// update local cache
		localCache.Set(AmCertificateRingKey, content)

		// udpate kv store
		AmStore.PutKVRing(AmCertificateRingKey, content)
	} else {
		// update local cache
		content, _ := json.Marshal(certificateData)
		localCache.Set(AmCertificateRingKey, string(content))
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
	_ = level.Debug(logger).Log("msg", fmt.Sprintf("vault certificate secrets list: %v", vaultSecrets))

	var vaultCertList []Certificate
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
	_ = level.Debug(logger).Log("msg", fmt.Sprintf("vault token secrets list: %v", vaultSecrets))

	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	tokenMap := make(map[string]Token)
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
