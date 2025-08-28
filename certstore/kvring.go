package certstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/memcache"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/ring"
)

var localCache = memcache.NewLocalCache()

func (c *CertStore) GetLocalCacheKeys() []string {
	return localCache.GetAllKeys()
}

func (c *CertStore) GetKVRingCert(key string, isLeader bool) ([]Certificate, error) {
	var data []Certificate

	content, err := c.GetKVRing(key, isLeader)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to get kv store key '%s'", key), "err", err)
		return data, err
	}

	// Handle empty content
	if content == "" {
		_ = level.Debug(c.Logger).Log("msg", fmt.Sprintf("Empty content for key '%s', returning empty slice", key))
		return data, nil
	}

	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err, "content", content)
		return data, err
	}
	return data, nil
}

func (c *CertStore) GetKVRingMapString(key string, isLeader bool) (map[string]string, error) {
	var data map[string]string
	content, err := c.GetKVRing(key, isLeader)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to get kv store key '%s'", key), "err", err)
		return data, err
	}

	// Handle empty content
	if content == "" {
		_ = level.Debug(c.Logger).Log("msg", fmt.Sprintf("Empty content for key '%s', returning empty map", key))
		return make(map[string]string), nil
	}

	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err, "content", content)
		return data, err
	}
	return data, nil
}

func (c *CertStore) GetKVRingToken(key string, isLeader bool) (map[string]Token, error) {
	var data map[string]Token
	content, err := c.GetKVRing(key, isLeader)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to get kv store key '%s'", key), "err", err)
		return data, err
	}

	// Handle empty content
	if content == "" {
		_ = level.Debug(c.Logger).Log("msg", fmt.Sprintf("Empty content for key '%s', returning empty map", key))
		return make(map[string]Token), nil
	}

	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err, "content", content)
		return data, err
	}
	return data, nil
}

func (c *CertStore) GetKVRing(key string, isLeader bool) (string, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	var data string

	if isLeader {
		if cached, found := localCache.Get(key); found {
			data = cached.Value.(string)
		}
	} else {
		ctx := context.Background()
		cached, err := c.RingConfig.JSONClient.Get(ctx, key)
		if err != nil {
			return data, err
		}

		if cached != nil {
			data = cached.(*ring.Data).Content
		}
	}

	return data, nil
}

func (c *CertStore) PutKVRing(key string, data interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	_ = level.Debug(c.Logger).Log("msg", fmt.Sprintf("Updating kv store key '%s'", key))

	content, _ := json.Marshal(data)
	c.updateKV(key, string(content))
	_ = level.Debug(c.Logger).Log("msg", fmt.Sprintf("Updated kv store key '%s'", key))
}

func (c *CertStore) updateKV(key, content string) {
	// update local cache
	localCache.Set(key, content)

	updatedAt := time.Now()
	data := &ring.Data{
		Content:   content,
		UpdatedAt: updatedAt,
	}

	ctx := context.Background()
	err := c.RingConfig.JSONClient.CAS(ctx, key, func(_ interface{}) (out interface{}, retry bool, err error) {
		return data, true, nil
	})

	if err != nil {
		_ = level.Error(c.Logger).Log("msg", "Failed to update KV store after retries", "key", key, "err", err)
	} else {
		metrics.SetKVDataUpdateTime(key, float64(updatedAt.Unix()))
	}
}

// KVSyncFromLeader - Leader pushes its state using CAS operations
func (c *CertStore) KVSyncFromLeader(leader string, keys []string) (map[string]interface{}, error) {
	keysToSync := keys
	if len(keysToSync) == 0 {
		keysToSync = localCache.GetAllKeys()
	}

	result := map[string]interface{}{
		"timestamp":   time.Now(),
		"total_keys":  len(keysToSync),
		"synced_keys": []string{},
		"failed_keys": []string{},
	}

	syncedKeys := []string{}
	failedKeys := []string{}

	for _, key := range keysToSync {
		if c.forceSyncKey(leader, key) {
			syncedKeys = append(syncedKeys, key)
		} else {
			failedKeys = append(failedKeys, key)
		}
	}

	result["synced_keys"] = syncedKeys
	result["failed_keys"] = failedKeys

	_ = level.Info(c.Logger).Log(
		"msg", "kv sync completed",
		"synced", len(syncedKeys),
		"failed", len(failedKeys),
	)

	return result, nil
}

// forceSyncKey - Force sync a single key
func (c *CertStore) forceSyncKey(leader, key string) bool {
	cached, found := localCache.Get(key)
	if !found {
		return false
	}

	updatedAt := time.Now()
	data := &ring.Data{
		Content:   cached.Value.(string),
		UpdatedAt: updatedAt,
		SyncedBy:  leader,
		Force:     true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := c.RingConfig.JSONClient.CAS(ctx, key, func(_ interface{}) (out interface{}, retry bool, err error) {
		return data, true, nil
	})

	if err == nil {
		metrics.SetKVDataUpdateTime(key, float64(updatedAt.Unix()))
	}
	return err == nil
}
