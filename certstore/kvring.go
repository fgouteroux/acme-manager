package certstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-kit/log/level"

	"github.com/grafana/dskit/kv/memberlist"

	"github.com/fgouteroux/acme_manager/memcache"
	"github.com/fgouteroux/acme_manager/ring"
)

var localCache = memcache.NewLocalCache()

func (c *CertStore) GetKVRingCert(key string, isLeader bool) ([]Certificate, error) {
	var data []Certificate

	content, err := c.GetKVRing(key, isLeader)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to get kv store key '%s'", key), "err", err)
		return data, err
	}

	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err)
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

	if content != "" {
		err = json.Unmarshal([]byte(content), &data)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err)
			return data, err
		}
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

	if content != "" {
		err = json.Unmarshal([]byte(content), &data)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to decode kv store key '%s' value", key), "err", err)
			return data, err
		}
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

	data := &ring.Data{
		Content:   content,
		CreatedAt: time.Now(),
	}

	val, err := ring.JSONCodec.Encode(data)
	if err != nil {
		_ = level.Error(c.Logger).Log("msg", fmt.Sprintf("Failed to encode data with '%s'", ring.JSONCodec.CodecID()), "err", err)
		return
	}

	msg := memberlist.KeyValuePair{
		Key:   key,
		Value: val,
		Codec: ring.JSONCodec.CodecID(),
	}

	msgBytes, _ := msg.Marshal()
	c.RingConfig.KvStore.NotifyMsg(msgBytes)
}
