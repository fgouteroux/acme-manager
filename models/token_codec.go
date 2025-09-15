package models

import (
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/grafana/dskit/kv/codec"
	"github.com/grafana/dskit/kv/memberlist"
)

// ProtoTokenFactory makes new Token
func ProtoTokenFactory() proto.Message {
	return NewToken()
}

// NewToken returns an empty *models.Token.
func NewToken() *Token {
	return &Token{}
}

// Merge merges other Token into this one.
// The decision is made based on the UpdatedAt timestamp
func (r *Token) Merge(other memberlist.Mergeable, _ bool) (memberlist.Mergeable, error) {
	return r.mergeWithTime(other)
}

func (r *Token) mergeWithTime(mergeable memberlist.Mergeable) (memberlist.Mergeable, error) {
	if mergeable == nil {
		return nil, nil
	}

	other, ok := mergeable.(*Token)
	if !ok {
		return nil, fmt.Errorf("expected *models.Token, got %T", mergeable)
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

	out := NewToken()
	*out = *r
	return out, nil
}

// MergeContent describes content of this Mergeable.
// Given that Token can have only one instance at a time, it returns the Token it contains. By doing this we choose
// to not make use of the subset invalidation feature of memberlist
func (r *Token) MergeContent() []string {
	result := []string(nil)
	if len(r.TokenHash) != 0 {
		result = append(result, r.String())
	}
	return result
}

// RemoveTombstones is noOp because we will handle Tokenetions outside the context of memberlist.
func (r *Token) RemoveTombstones(_ time.Time) (total, removed int) {
	return
}

// Clone returns a deep copy of the Token.
func (r *Token) Clone() memberlist.Mergeable {
	return proto.Clone(r).(*Token)
}

func GetTokenCodec() codec.Proto {
	return codec.NewProtoCodec("Token", ProtoTokenFactory)
}
