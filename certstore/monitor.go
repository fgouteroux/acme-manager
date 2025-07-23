package certstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/ring"
)

// Monitor monitors KV data consistency by calculating SHA256 hashes
type Monitor struct {
	logger   log.Logger
	interval time.Duration
}

// NewMonitor creates a new KV hash monitor
func NewMonitor(logger log.Logger, interval time.Duration) *Monitor {
	return &Monitor{
		logger:   log.With(logger, "component", "kv_hash_monitor"),
		interval: interval,
	}
}

// calculateDataHash calculates SHA256 hash of data content
func (mon *Monitor) calculateDataHash(content string) float64 {
	if content == "" {
		return 0.0
	}

	hash := sha256.Sum256([]byte(content))
	hashHex := hex.EncodeToString(hash[:])

	// Convert first 8 hex chars to float64 for Prometheus gauge
	hashFloat := 0.0
	if len(hashHex) >= 8 {
		if hashInt, err := strconv.ParseInt(hashHex[:8], 16, 64); err == nil {
			hashFloat = float64(hashInt)
		}
	}

	return hashFloat
}

// getRole determines if this node is leader or follower
func (mon *Monitor) getRole() int {
	isLeader, err := ring.IsLeader(AmStore.RingConfig)
	if err != nil {
		_ = level.Warn(mon.logger).Log("msg", "Failed to determine role", "err", err)
		return 0
	}

	if isLeader {
		return 1
	}
	return 2
}

// monitorKvKey calculates hash for a specific key
func (mon *Monitor) monitorKvKey(key string) {
	role := mon.getRole()
	// Always get data from both sources for consistent comparison

	// Get data from ring (non-leader path to ensure we get ring data)
	ringContent, err := AmStore.GetKVRing(key, false)
	if err != nil {
		_ = level.Error(mon.logger).Log("msg", "Failed to get KV ring data for hash calculation", "key", key, "err", err)
		metrics.IncKvHashErrorsTotal(key, "ring", "get_kv_error")
		return
	}

	// Get data from local cache directly
	var cacheContent string
	cached, found := localCache.Get(key)
	if !found {
		_ = level.Error(mon.logger).Log("msg", "Failed to get KV cache data for hash calculation", "key", key)
		metrics.IncKvHashErrorsTotal(key, "cache", "get_kv_error")
		return
	}

	// Handle the cache content
	switch v := cached.Value.(type) {
	case string:
		cacheContent = v
	case []byte:
		cacheContent = string(v)
	default:
		_ = level.Error(mon.logger).Log("msg", "Unexpected cache value type", "key", key, "type", fmt.Sprintf("%T", v))
		metrics.IncKvHashErrorsTotal(key, "cache", "type_error")
		return
	}

	// Calculate hashes
	ringHashFloat := mon.calculateDataHash(ringContent)
	cacheHashFloat := mon.calculateDataHash(cacheContent)

	// Update metrics
	metrics.SetKvDataHashGauge(key, "ring", ringHashFloat)
	metrics.SetKvDataLengthGauge(key, "ring", float64(len(ringContent)))
	metrics.SetKvDataHashGauge(key, "cache", cacheHashFloat)
	metrics.SetKvDataLengthGauge(key, "cache", float64(len(cacheContent)))
	metrics.SetNodeRole(float64(role))

	// Check for leader status for logging context
	isLeaderNow, _ := ring.IsLeader(AmStore.RingConfig)

	// Debug logging
	_ = level.Debug(mon.logger).Log(
		"msg", "Data comparison",
		"key", key,
		"ring_length", len(ringContent),
		"cache_length", len(cacheContent),
		"is_leader", isLeaderNow,
		"hashes_match", ringHashFloat == cacheHashFloat,
	)

	if ringHashFloat != cacheHashFloat {
		// Log detailed hash information for debugging
		_ = level.Warn(mon.logger).Log(
			"msg", "KV ring/cache data hash mismatch",
			"key", key,
			"ring_hash", ringHashFloat,
			"cache_hash", cacheHashFloat,
			"ring_length", len(ringContent),
			"cache_length", len(cacheContent),
			"is_leader", isLeaderNow,
		)
	} else {
		_ = level.Debug(mon.logger).Log(
			"msg", "Ring and cache data match",
			"key", key,
			"hash", ringHashFloat,
		)
	}
}

// MonitorPeriodically starts periodic hash calculation for all keys
func (mon *Monitor) MonitorPeriodically(ctx context.Context) {
	_ = level.Info(mon.logger).Log("msg", "Starting KV hash monitoring", "interval", mon.interval)

	ticker := time.NewTicker(mon.interval)
	defer ticker.Stop()

	// Define the keys to monitor
	keysToMonitor := []string{
		AmCertificateRingKey, // "collectors/certificate"
		AmTokenRingKey,       // "collectors/tokens"
		AmChallengeRingKey,   // "collectors/challenges"
	}

	// Run immediately on start
	mon.monitorAllKvKeys(keysToMonitor)

	for {
		select {
		case <-ctx.Done():
			_ = level.Info(mon.logger).Log("msg", "Stopping KV hash monitoring")
			return
		case <-ticker.C:
			mon.monitorAllKvKeys(keysToMonitor)
		}
	}
}

// monitorAllKvKeys monitors all keys in a single cycle
func (mon *Monitor) monitorAllKvKeys(keys []string) {
	_ = level.Debug(mon.logger).Log("msg", "Starting hash monitoring cycle")

	for _, key := range keys {
		mon.monitorKvKey(key)
	}

	_ = level.Debug(mon.logger).Log("msg", "Completed hash monitoring cycle")
}

func StartMonitoring(logger log.Logger) {
	interval := 30 * time.Second
	monitor := NewMonitor(logger, interval)

	// Start monitoring in a separate goroutine
	go monitor.MonitorPeriodically(context.Background())
}
