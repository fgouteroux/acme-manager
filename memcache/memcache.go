package memcache

import (
	"sync"
)

type MemCache struct {
	data map[string]CacheValue
	lock sync.Mutex
}

type CacheValue struct {
	Value interface{}
}

func NewLocalCache() *MemCache {
	return &MemCache{
		data: make(map[string]CacheValue),
	}
}

func (c *MemCache) Set(key string, value interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.data[key] = CacheValue{
		Value: value,
	}
}

func (c *MemCache) Get(key string) (CacheValue, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	value, found := c.data[key]
	return value, found
}

func (c *MemCache) Del(key string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.data, key)
}
