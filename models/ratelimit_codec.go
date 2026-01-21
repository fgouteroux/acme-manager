package models

import (
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/grafana/dskit/kv/codec"
	"github.com/grafana/dskit/kv/memberlist"
)

// ProtoRateLimitFactory makes new RateLimit
func ProtoRateLimitFactory() proto.Message {
	return NewRateLimit()
}

// NewRateLimit returns an empty *models.RateLimit.
func NewRateLimit() *RateLimit {
	return &RateLimit{}
}

// Merge merges other RateLimit into this one.
// The decision is made based on the UpdatedAt timestamp
func (r *RateLimit) Merge(other memberlist.Mergeable, _ bool) (memberlist.Mergeable, error) {
	return r.mergeWithTime(other)
}

func (r *RateLimit) mergeWithTime(mergeable memberlist.Mergeable) (memberlist.Mergeable, error) {
	if mergeable == nil {
		return nil, nil
	}

	other, ok := mergeable.(*RateLimit)
	if !ok {
		return nil, fmt.Errorf("expected *models.RateLimit, got %T", mergeable)
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

	out := NewRateLimit()
	*out = *r
	return out, nil
}

// MergeContent describes content of this Mergeable.
func (r *RateLimit) MergeContent() []string {
	result := []string(nil)
	if len(r.Owner) != 0 {
		result = append(result, r.String())
	}
	return result
}

// RemoveTombstones is noOp because we will handle deletions outside the context of memberlist.
func (r *RateLimit) RemoveTombstones(_ time.Time) (total, removed int) {
	return
}

// Clone returns a deep copy of the RateLimit.
func (r *RateLimit) Clone() memberlist.Mergeable {
	return proto.Clone(r).(*RateLimit)
}

func GetRateLimitCodec() codec.Proto {
	return codec.NewProtoCodec("RateLimit", ProtoRateLimitFactory)
}
