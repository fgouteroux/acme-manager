package certstore

import "errors"

var (
	// ErrNotFound is returned when a requested certificate, token or challenge
	// does not exist in the KV ring. Callers should use errors.Is to detect it
	// rather than matching on the error message text.
	ErrNotFound = errors.New("not found")

	// ErrPendingDeletion is returned when an entry still exists in the KV ring
	// but has been marked for deletion (DeletedAt > 0). Callers should use
	// errors.Is to detect it rather than matching on the error message text.
	ErrPendingDeletion = errors.New("pending deletion")
)
