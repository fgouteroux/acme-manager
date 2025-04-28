package memcache

import (
	"sync"
	"testing"
)

func TestMemCache(t *testing.T) {
	cache := NewLocalCache()

	// Test Set and Get
	key := "testKey"
	value := "testValue"
	cache.Set(key, value)

	retrievedValue, found := cache.Get(key)
	if !found {
		t.Fatalf("Expected to find key %s", key)
	}
	if retrievedValue.Value != value {
		t.Fatalf("Expected value %v, but got %v", value, retrievedValue.Value)
	}

	// Test Del
	cache.Del(key)
	_, found = cache.Get(key)
	if found {
		t.Fatalf("Expected key %s to be deleted", key)
	}
}

func TestMemCacheConcurrentAccess(t *testing.T) {
	cache := NewLocalCache()
	key := "concurrentKey"
	value := "concurrentValue"

	// Set value concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.Set(key, value)
		}()
	}
	wg.Wait()

	// Verify value
	retrievedValue, found := cache.Get(key)
	if !found {
		t.Fatalf("Expected to find key %s", key)
	}
	if retrievedValue.Value != value {
		t.Fatalf("Expected value %v, but got %v", value, retrievedValue.Value)
	}

	// Delete value concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.Del(key)
		}()
	}
	wg.Wait()

	// Verify deletion
	_, found = cache.Get(key)
	if found {
		t.Fatalf("Expected key %s to be deleted", key)
	}
}
