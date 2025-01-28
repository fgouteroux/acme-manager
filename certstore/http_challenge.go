// Package certstore implements an HTTP provider for solving the HTTP-01 challenge using kvring in combination with a webserver.
package certstore

import (
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-kit/log"

	"github.com/fgouteroux/acme_manager/queue"
	"github.com/fgouteroux/acme_manager/ring"
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
	action := func() error {

		isLeader, err := ring.IsLeader(AmStore.RingConfig)
		if err != nil {
			return err
		}

		data, err := AmStore.GetKVRingMapString(AmChallengeRingKey, isLeader)
		if err != nil {
			return err
		}

		if data == nil {
			data = make(map[string]string)
		}

		data[http01.ChallengePath(token)] = keyAuth

		AmStore.PutKVRing(AmChallengeRingKey, data)
		return nil
	}

	ChallengeQueue.AddJob(queue.Job{
		Name:   http01.ChallengePath(token),
		Action: action,
	}, w.logger)

	return nil
}

// CleanUp removes the file created for the challenge.
func (w *HTTPProvider) CleanUp(_, token, _ string) error {

	action := func() error {

		isLeader, err := ring.IsLeader(AmStore.RingConfig)
		if err != nil {
			return err
		}

		data, err := AmStore.GetKVRingMapString(AmChallengeRingKey, isLeader)
		if err != nil {
			return err
		}

		delete(data, http01.ChallengePath(token))

		AmStore.PutKVRing(AmChallengeRingKey, data)
		return nil
	}

	ChallengeQueue.AddJob(queue.Job{
		Name:   http01.ChallengePath(token),
		Action: action,
	}, w.logger)

	return nil
}
