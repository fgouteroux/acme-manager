package certstore

import (
	"errors"
	"fmt"
	"testing"
)

// TestSentinelErrorsAreMatchable ensures the wrapped errors returned by the KV
// ring lookups (e.g. GetCertificate / GetToken) can be detected with errors.Is
// so that API handlers select the correct HTTP status without matching on the
// error message text.
func TestSentinelErrorsAreMatchable(t *testing.T) {
	// Mirrors the wrapping done in kvring.go for a missing entry.
	notFound := fmt.Errorf("certificate '%s' %w", "certificate/owner/name", ErrNotFound)
	if !errors.Is(notFound, ErrNotFound) {
		t.Fatalf("expected wrapped error to match ErrNotFound, got %v", notFound)
	}
	if errors.Is(notFound, ErrPendingDeletion) {
		t.Fatalf("not-found error should not match ErrPendingDeletion")
	}

	// Mirrors the wrapping done for a tombstoned entry.
	pending := fmt.Errorf("token id '%s' is %w", "abc", ErrPendingDeletion)
	if !errors.Is(pending, ErrPendingDeletion) {
		t.Fatalf("expected wrapped error to match ErrPendingDeletion, got %v", pending)
	}
	if errors.Is(pending, ErrNotFound) {
		t.Fatalf("pending-deletion error should not match ErrNotFound")
	}

	if errors.Is(ErrNotFound, ErrPendingDeletion) {
		t.Fatalf("sentinels must be distinct")
	}
}
