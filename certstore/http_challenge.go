// Package certstore implements an HTTP provider for solving the HTTP-01 challenge.
//
// Challenges are held in local process memory rather than in the memberlist ring:
// the ACME HTTP-01 token is a random, single-use value, so storing one KV key per
// challenge would gossip every ephemeral token cluster-wide and leak a per-key
// worker goroutine that dskit never reaps. Instead the leader (which runs the ACME
// order) keeps the key authorization locally, and validation requests that land on
// a follower are forwarded to the leader (see httpChallengeHandler).
package certstore

import (
	"context"
	"fmt"

	"github.com/go-kit/log"

	"github.com/fgouteroux/acme-manager/memcache"
)

// challengeStore holds HTTP-01 key authorizations (token -> keyAuth) in local
// process memory. Entries are added on Present and removed on CleanUp.
var challengeStore = memcache.NewLocalCache()

// HTTPProvider implements lego's challenge.Provider for the `http-01` challenge.
type HTTPProvider struct {
	logger log.Logger
}

// NewKVRingProvider returns an HTTPProvider instance. The name is kept for
// config backward-compatibility (challenge provider "kvring"); challenges are now
// served from local memory with leader forwarding, not from the ring.
func NewKVRingProvider(logger log.Logger) (*HTTPProvider, error) {
	return &HTTPProvider{logger: logger}, nil
}

// Present makes the token available at `HTTP01ChallengePath(token)`.
func (w *HTTPProvider) Present(_ context.Context, _, token, keyAuth string) error {
	return AmStore.PutChallenge(token, keyAuth)
}

// CleanUp removes the challenge for the given token.
func (w *HTTPProvider) CleanUp(_ context.Context, _, token, _ string) error {
	return AmStore.DeleteChallenge(token)
}

// PutChallenge stores a challenge key authorization in local process memory.
func (c *CertStore) PutChallenge(token, keyAuth string) error {
	challengeStore.Set(token, keyAuth)
	return nil
}

// GetChallenge returns the key authorization for the given token from local
// memory, wrapping ErrNotFound when absent (matched by the HTTP-01 handler to
// return 404, and by followers to forward to the leader).
func (c *CertStore) GetChallenge(token string) (string, error) {
	cached, found := challengeStore.Get(token)
	if !found {
		return "", fmt.Errorf("challenge id '%s' %w", token, ErrNotFound)
	}
	keyAuth, ok := cached.Value.(string)
	if !ok {
		return "", fmt.Errorf("unexpected type %T for challenge id '%s'", cached.Value, token)
	}
	return keyAuth, nil
}

// DeleteChallenge removes a challenge from local memory.
func (c *CertStore) DeleteChallenge(token string) error {
	challengeStore.Del(token)
	return nil
}
