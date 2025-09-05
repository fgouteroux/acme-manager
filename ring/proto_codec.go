package ring

import (
	"fmt"
	"time"

	"github.com/grafana/dskit/kv/codec"
	"github.com/grafana/dskit/kv/memberlist"
	"github.com/gogo/protobuf/proto"
	"github.com/prometheus/prometheus/model/timestamp"
)

// The generated Data struct from protobuf will automatically implement proto.Message
// We need to add the memberlist.Mergeable methods to it

// Merge implements the memberlist.Mergeable interface for the protobuf Data struct
func (d *Data) Merge(mergeable memberlist.Mergeable, _ bool) (memberlist.Mergeable, error) {
	if mergeable == nil {
		return nil, nil
	}
	
	other, ok := mergeable.(*Data)
	if !ok {
		return nil, fmt.Errorf("expected *Data, got %T", mergeable)
	}
	if other == nil {
		return nil, nil
	}

	changed := false
	
	// Compare timestamps
	if other.UpdatedAt > d.UpdatedAt {
		*d = *other
		changed = true
	}

	// No changes
	if !changed {
		return nil, nil
	}

	// Return a copy
	out := NewData()
	*out = *d
	return out, nil
}

// MergeContent returns the content for comparison
func (d *Data) MergeContent() []string {
	result := []string(nil)
	if len(d.Content) != 0 {
		result = append(result, d.String())
	}
	return result
}

// RemoveTombstones
func (d *Data) RemoveTombstones(_ time.Time) (total, removed int) {
	return
}

// Clone creates a deep copy using gogo/protobuf
func (d *Data) Clone() memberlist.Mergeable {
	return proto.Clone(d).(*Data)
}

// ProtoDataFactory creates new Data instances
func ProtoDataFactory() proto.Message {
	return NewData()
}

// NewData returns an empty *Data
func NewData() *Data {
	return &Data{
		UpdatedAt: timestamp.FromTime(time.Now()),
	}
}

// GetDataCodec returns a protobuf codec for Data messages
func GetDataCodec() codec.Proto {
	return codec.NewProtoCodec("dataCodec", ProtoDataFactory)
}

// Helper functions for creating protobuf data

// NewDataWithContent creates a new Data with content
func NewDataWithContent(content string ) *Data {
	return &Data{
		Content:   content,
		UpdatedAt: timestamp.FromTime(time.Now()),
	}
}

// Helper to convert from your existing JSON-based cache to protobuf
func DataFromCache(content string, updatedAt time.Time) *Data {
	return &Data{
		Content:   content,
		UpdatedAt: timestamp.FromTime(updatedAt),
	}
}