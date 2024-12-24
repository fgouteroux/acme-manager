// Package certstore implements an HTTP provider for solving the HTTP-01 challenge using kvring in combination with a webserver.
package certstore

import (
	"github.com/go-acme/lego/v4/challenge/http01"
)

// HTTPProvider implements HTTPProvider for `http-01` challenge.
type HTTPProvider struct{}

// NewMemcacheProvider returns a HTTPProvider instance with a configured webroot path.
func NewKVRingProvider() (*HTTPProvider, error) {
	return &HTTPProvider{}, nil
}

// Present makes the token available at `HTTP01ChallengePath(token)` by creating the key in the kvring.
func (w *HTTPProvider) Present(_, token, keyAuth string) error {
	data, err := AmStore.GetKVRingMapString(AmRingChallengeKey)
	if err != nil {
		return err
	}

	if data == nil {
		data = make(map[string]string)
	}
	data[http01.ChallengePath(token)] = keyAuth

	AmStore.PutKVRing(AmRingChallengeKey, data)
	return nil
}

// CleanUp removes the file created for the challenge.
func (w *HTTPProvider) CleanUp(_, token, _ string) error {
	data, err := AmStore.GetKVRingMapString(AmRingChallengeKey)
	if err != nil {
		return err
	}
	delete(data, http01.ChallengePath(token))
	AmStore.PutKVRing(AmRingChallengeKey, data)
	return nil
}
