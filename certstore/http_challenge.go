// Package certstore implements an HTTP provider for solving the HTTP-01 challenge using kvring in combination with a webserver.
package certstore

import (
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-kit/log"
)

// HTTPProvider implements HTTPProvider for `http-01` challenge.
type HTTPProvider struct {
	logger log.Logger
}

// NewMemcacheProvider returns a HTTPProvider instance with a configured webroot path.
func NewKVRingProvider(logger log.Logger) (*HTTPProvider, error) {
	return &HTTPProvider{logger: logger}, nil
}

// Present makes the token available at `HTTP01ChallengePath(token)` by creating the key in the kvring.
func (w *HTTPProvider) Present(_, token, keyAuth string) error {
	key := GenerateChallengeKey(http01.ChallengePath(token))
	return AmStore.PutChallenge(key, keyAuth)
}

// CleanUp removes the file created for the challenge.
func (w *HTTPProvider) CleanUp(_, token, _ string) error {
	key := GenerateChallengeKey(http01.ChallengePath(token))
	return AmStore.DeleteChallenge(key)
}
