package ring

import (
	"fmt"
	"time"

	"github.com/grafana/dskit/kv/codec"
	"github.com/grafana/dskit/kv/memberlist"
	"github.com/gogo/protobuf/proto"  // Use gogo/protobuf like Mimir
	"github.com/prometheus/prometheus/model/timestamp"  // Use Mimir's timestamp handling
)

// The generated Data struct from protobuf will automatically implement proto.Message
// We need to add the memberlist.Mergeable methods to it

// Merge implements the memberlist.Mergeable interface for the protobuf Data struct
// Following the same pattern as Mimir's ReplicaDesc.Merge
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
	
	// Use the same logic as Mimir - compare timestamps
	if other.UpdatedAt > d.UpdatedAt {
		*d = *other
		changed = true
	} else if d.UpdatedAt == other.UpdatedAt && d.Force == false && other.Force == true {
		// If timestamps are equal, prefer the one with Force=true
		*d = *other
		changed = true
	}

	// No changes
	if !changed {
		return nil, nil
	}

	// Return a copy like Mimir does
	out := NewData()
	*out = *d
	return out, nil
}

// MergeContent returns the content for comparison - same pattern as Mimir
func (d *Data) MergeContent() []string {
	result := []string(nil)
	if len(d.Content) != 0 {
		result = append(result, d.String())
	}
	return result
}

// RemoveTombstones - following Mimir's pattern
func (d *Data) RemoveTombstones(_ time.Time) (total, removed int) {
	return
}

// Clone creates a deep copy using gogo/protobuf - same as Mimir
func (d *Data) Clone() memberlist.Mergeable {
	return proto.Clone(d).(*Data)
}

// ProtoDataFactory creates new Data instances - exact same pattern as Mimir's ProtoReplicaDescFactory
func ProtoDataFactory() proto.Message {
	return NewData()
}

// NewData returns an empty *Data - same pattern as Mimir's NewReplicaDesc
func NewData() *Data {
	return &Data{
		UpdatedAt: timestamp.FromTime(time.Now()),  // Use Mimir's timestamp handling
	}
}

// GetDataCodec returns a protobuf codec for Data messages - exact same pattern as Mimir's GetReplicaDescCodec
func GetDataCodec() codec.Proto {
	return codec.NewProtoCodec("dataCodec", ProtoDataFactory)
}

// Helper functions for creating protobuf data

// NewDataWithContent creates a new Data with content
func NewDataWithContent(content, syncedBy string, force bool) *Data {
	return &Data{
		Content:   content,
		SyncedBy:  syncedBy,
		UpdatedAt: timestamp.FromTime(time.Now()),
		Force:     force,
	}
}

// Helper to convert from your existing JSON-based cache to protobuf
func DataFromCache(content string, syncedBy string, updatedAt time.Time, force bool) *Data {
	return &Data{
		Content:   content,
		SyncedBy:  syncedBy,
		UpdatedAt: timestamp.FromTime(updatedAt),
		Force:     force,
	}
}