package certstore

import (
	"encoding/json"
	"sort"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/queue"
)

func checkCertificateConsistency(logger log.Logger) {
	action := func() error {
		// Get certificates from vault
		vaultCertList, err := getVaultAllCertificate(logger)
		if err != nil {
			_ = level.Error(logger).Log("msg", "Failed to get certificates from vault", "err", err)
			return nil
		}

		// Get certificates from KV ring
		ringCertificates, err := AmStore.GetKVRingCert(AmCertificateRingKey, true) // true because we're the leader
		if err != nil {
			_ = level.Error(logger).Log("msg", "Failed to get certificates from KV ring", "err", err)
			return nil
		}

		// Compare the slices using deep JSON comparison
		if !areCertificateSlicesEqualDeep(vaultCertList, ringCertificates) {
			_ = level.Info(logger).Log("msg", "Certificate KV ring not consistent with vault, updating",
				"vault_count", len(vaultCertList),
				"ring_count", len(ringCertificates),
				"key", AmCertificateRingKey)

			// Update KV ring with vault data (no error return)
			AmStore.PutKVRing(AmCertificateRingKey, vaultCertList)
			_ = level.Info(logger).Log("msg", "Successfully updated certificate KV ring", "count", len(vaultCertList))
		} else {
			_ = level.Info(logger).Log("msg", "Certificate KV ring is consistent with vault", "count", len(vaultCertList))
		}
		return nil
	}

	CertificateQueue.AddJob(queue.Job{
		Name:   "check-kvring-certificate-consistency",
		Action: action,
	}, logger)
}

func checkTokenConsistency(logger log.Logger) {
	action := func() error {
		// Get tokens from vault
		vaultTokenMap, err := getVaultAllToken(logger)
		if err != nil {
			_ = level.Error(logger).Log("msg", "Failed to get tokens from vault", "err", err)
			return nil
		}

		// Get tokens from KV ring
		ringTokenMap, err := AmStore.GetKVRingToken(AmTokenRingKey, true) // true because we're the leader
		if err != nil {
			_ = level.Error(logger).Log("msg", "Failed to get tokens from KV ring", "err", err)
			return nil
		}

		// Compare the maps using deep JSON comparison
		if !areTokenMapsEqualDeep(vaultTokenMap, ringTokenMap) {
			_ = level.Info(logger).Log("msg", "Token KV ring not consistent with vault, updating",
				"vault_count", len(vaultTokenMap),
				"ring_count", len(ringTokenMap),
				"key", AmTokenRingKey)

			// Update KV ring with vault data (no error return)
			AmStore.PutKVRing(AmTokenRingKey, vaultTokenMap)
			_ = level.Info(logger).Log("msg", "Successfully updated token KV ring", "count", len(vaultTokenMap))
		} else {
			_ = level.Info(logger).Log("msg", "Token KV ring is consistent with vault", "count", len(vaultTokenMap))
		}
		return nil
	}

	TokenQueue.AddJob(queue.Job{
		Name:   "check-kvring-token-consistency",
		Action: action,
	}, logger)
}


// areCertificateSlicesEqualDeep compares two Certificate slices using JSON marshaling
func areCertificateSlicesEqualDeep(a, b []Certificate) bool {
	if len(a) != len(b) {
		return false
	}

	// Sort both slices first
	aCopy := make([]Certificate, len(a))
	bCopy := make([]Certificate, len(b))
	copy(aCopy, a)
	copy(bCopy, b)

	sortCertificates := func(certs []Certificate) {
		sort.Slice(certs, func(i, j int) bool {
			if certs[i].Domain != certs[j].Domain {
				return certs[i].Domain < certs[j].Domain
			}
			if certs[i].Issuer != certs[j].Issuer {
				return certs[i].Issuer < certs[j].Issuer
			}
			return certs[i].Owner < certs[j].Owner
		})
	}

	sortCertificates(aCopy)
	sortCertificates(bCopy)

	// Marshal both to JSON and compare
	aJSON, err := json.Marshal(aCopy)
	if err != nil {
		return false
	}

	bJSON, err := json.Marshal(bCopy)
	if err != nil {
		return false
	}

	return string(aJSON) == string(bJSON)
}

// areTokenMapsEqualDeep compares two Token maps using JSON marshaling
func areTokenMapsEqualDeep(a, b map[string]Token) bool {
	if len(a) != len(b) {
		return false
	}

	// Marshal both maps to JSON and compare
	aJSON, err := json.Marshal(a)
	if err != nil {
		return false
	}

	bJSON, err := json.Marshal(b)
	if err != nil {
		return false
	}

	return string(aJSON) == string(bJSON)
}
