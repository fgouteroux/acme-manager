package certstore

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenExpiryDays(t *testing.T) {
	t.Run("never expires", func(t *testing.T) {
		got, err := tokenExpiryDays("Never")
		assert.NoError(t, err)
		assert.True(t, math.IsInf(got, 1), "expected +Inf, got %v", got)
	})

	t.Run("future date", func(t *testing.T) {
		expires := time.Now().UTC().Add(72 * time.Hour).Format("2006-01-02 15:04:05 -0700 MST")
		got, err := tokenExpiryDays(expires)
		assert.NoError(t, err)
		assert.Equal(t, float64(2), got)
	})

	t.Run("already expired", func(t *testing.T) {
		expires := time.Now().UTC().Add(-48 * time.Hour).Format("2006-01-02 15:04:05 -0700 MST")
		got, err := tokenExpiryDays(expires)
		assert.NoError(t, err)
		assert.Equal(t, float64(-2), got)
	})

	t.Run("malformed date", func(t *testing.T) {
		_, err := tokenExpiryDays("not-a-date")
		assert.Error(t, err)
	})
}
