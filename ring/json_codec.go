package ring

import (
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/grafana/dskit/kv/memberlist"
)

type Data struct {
	Content   string    `json:"content"`
	SyncedBy  string    `json:"synced_by"`
	UpdatedAt time.Time `json:"updated_at"`
	Force     bool      `json:"force"`
}

// Merge implements the memberlist.Mergeable interface.
// It allow to merge the content of two different data.
// We dont need to compare values to know if a change is requested as the leader only could send a message
func (c *Data) Merge(mergeable memberlist.Mergeable, _ bool) (memberlist.Mergeable, error) {
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

	if other.UpdatedAt.Before(c.UpdatedAt) {
		return nil, nil
	}

	if c.UpdatedAt.Equal(other.UpdatedAt) {
		return nil, nil
	}

	// request a change.
	*c = *other
	return other, nil
}

// MergeContent tells if the content of the two objects are the same.
func (c *Data) MergeContent() []string {
	return []string{c.Content}
}

// RemoveTombstones is not required
func (c *Data) RemoveTombstones(_ time.Time) (total, removed int) {
	return 0, 0
}

func (c *Data) Clone() memberlist.Mergeable {
	clone := *c
	return &clone
}

var JSONCodec = jsonCodec{}

type jsonCodec struct{}

func (jsonCodec) Decode(data []byte) (interface{}, error) {
	var value Data
	if err := jsoniter.ConfigFastest.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (jsonCodec) Encode(obj interface{}) ([]byte, error) {
	return jsoniter.ConfigFastest.Marshal(obj)
}
func (jsonCodec) CodecID() string { return "jsonCodec" }
