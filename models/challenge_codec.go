package models

import (
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/grafana/dskit/kv/codec"
	"github.com/grafana/dskit/kv/memberlist"
)

// ProtoChallengeFactory makes new Challenge
func ProtoChallengeFactory() proto.Message {
	return NewChallenge()
}

// NewChallenge returns an empty *models.Challenge.
func NewChallenge() *Challenge {
	return &Challenge{}
}

// Merge merges other Challenge into this one.
// The decision is made based on the UpdatedAt timestamp
func (r *Challenge) Merge(other memberlist.Mergeable, _ bool) (memberlist.Mergeable, error) {
	return r.mergeWithTime(other)
}

func (r *Challenge) mergeWithTime(mergeable memberlist.Mergeable) (memberlist.Mergeable, error) {
	if mergeable == nil {
		return nil, nil
	}

	other, ok := mergeable.(*Challenge)
	if !ok {
		return nil, fmt.Errorf("expected *models.Challenge, got %T", mergeable)
	}

	if other == nil {
		return nil, nil
	}

	changed := false
	if other.UpdatedAt > r.UpdatedAt {
		*r = *other
		changed = true
	} else if r.UpdatedAt == other.UpdatedAt && r.DeletedAt == 0 && other.DeletedAt != 0 {
		*r = *other
		changed = true
	}

	// No changes
	if !changed {
		return nil, nil
	}

	out := NewChallenge()
	*out = *r
	return out, nil
}

// MergeContent describes content of this Mergeable.
// Given that Challenge can have only one instance at a time, it returns the Challenge it contains. By doing this we choose
// to not make use of the subset invalidation feature of memberlist
func (r *Challenge) MergeContent() []string {
	result := []string(nil)
	if len(r.KeyAuth) != 0 {
		result = append(result, r.String())
	}
	return result
}

// RemoveTombstones is noOp because we will handle Challengeetions outside the context of memberlist.
func (r *Challenge) RemoveTombstones(_ time.Time) (total, removed int) {
	return
}

// Clone returns a deep copy of the Challenge.
func (r *Challenge) Clone() memberlist.Mergeable {
	return proto.Clone(r).(*Challenge)
}

func GetChallengeCodec() codec.Proto {
	return codec.NewProtoCodec("Challenge", ProtoChallengeFactory)
}
