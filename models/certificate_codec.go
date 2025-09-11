package models

import (
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/grafana/dskit/kv/codec"
	"github.com/grafana/dskit/kv/memberlist"
)

// ProtoCertificateFactory makes new Certificate
func ProtoCertificateFactory() proto.Message {
	return NewCertificate()
}

// NewCertificate returns an empty *models.Certificate.
func NewCertificate() *Certificate {
	return &Certificate{}
}

// Merge merges other Certificate into this one.
// The decision is made based on the UpdatedAt timestamp
func (r *Certificate) Merge(other memberlist.Mergeable, _ bool) (memberlist.Mergeable, error) {
	return r.mergeWithTime(other)
}

func (r *Certificate) mergeWithTime(mergeable memberlist.Mergeable) (memberlist.Mergeable, error) {
	if mergeable == nil {
		return nil, nil
	}

	other, ok := mergeable.(*Certificate)
	if !ok {
		return nil, fmt.Errorf("expected *models.Certificate, got %T", mergeable)
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

	out := NewCertificate()
	*out = *r
	return out, nil
}

// MergeContent describes content of this Mergeable.
// Given that Certificate can have only one instance at a time, it returns the Certificate it contains. By doing this we choose
// to not make use of the subset invalidation feature of memberlist
func (r *Certificate) MergeContent() []string {
	result := []string(nil)
	if len(r.Domain) != 0 {
		result = append(result, r.String())
	}
	return result
}

// RemoveTombstones is noOp because we will handle Certificateetions outside the context of memberlist.
func (r *Certificate) RemoveTombstones(_ time.Time) (total, removed int) {
	return
}

// Clone returns a deep copy of the Certificate.
func (r *Certificate) Clone() memberlist.Mergeable {
	return proto.Clone(r).(*Certificate)
}

func GetCertificateCodec() codec.Proto {
	return codec.NewProtoCodec("Certificate", ProtoCertificateFactory)
}
