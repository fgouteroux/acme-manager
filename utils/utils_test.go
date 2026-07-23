package utils

import (
	"strings"
	"testing"

	"github.com/go-kit/log"
)

func TestSanitizedDomain(t *testing.T) {
	logger := log.NewNopLogger()

	tests := []struct {
		name    string
		domain  string
		want    string
		wantErr bool
	}{
		{name: "valid", domain: "example.com", want: "example.com"},
		{name: "valid subdomain", domain: "api.example.com", want: "api.example.com"},
		{name: "wildcard", domain: "*.example.com", want: "_.example.com"},
		{name: "empty", domain: "", wantErr: true},
		{name: "wildcard non-leading", domain: "example.*.com", wantErr: true},
		{name: "bad chars", domain: "exa mple.com", wantErr: true},
		{name: "empty label", domain: "example..com", wantErr: true},
		{name: "too long", domain: strings.Repeat("a", 254) + ".com", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizedDomain(logger, tc.domain)
			if tc.wantErr {
				if err == nil {
					t.Errorf("SanitizedDomain(%q) expected error, got nil (result %q)", tc.domain, got)
				}
				return
			}
			if err != nil {
				t.Errorf("SanitizedDomain(%q) unexpected error: %v", tc.domain, err)
			}
			if got != tc.want {
				t.Errorf("SanitizedDomain(%q) = %q, want %q", tc.domain, got, tc.want)
			}
		})
	}
}

func TestRedactHeaderValue(t *testing.T) {
	if got := redactHeaderValue("Authorization", "Bearer secret"); got != redactedPlaceholder {
		t.Errorf("Authorization value not redacted, got %q", got)
	}
	if got := redactHeaderValue("x-api-key", "abc123"); got != redactedPlaceholder {
		t.Errorf("X-API-Key value not redacted (case-insensitive), got %q", got)
	}
	if got := redactHeaderValue("Content-Type", "application/json"); got != "application/json" {
		t.Errorf("non-secret header should not be redacted, got %q", got)
	}
}

func TestRedactBody(t *testing.T) {
	in := `{"token":"abc","secret_id":"sid","hmac":"h","name":"keep"}`
	out := redactBody(in)
	for _, secret := range []string{"abc", "sid", `"hmac":"h"`} {
		if strings.Contains(out, secret) {
			t.Errorf("redactBody left a secret in output: %q -> %q", secret, out)
		}
	}
	if !strings.Contains(out, "keep") {
		t.Errorf("redactBody should preserve non-secret fields, got %q", out)
	}
	if strings.Count(out, redactedPlaceholder) != 3 {
		t.Errorf("expected 3 redacted fields, got %q", out)
	}

	// Non-JSON body must be returned unchanged and not crash.
	plain := "not json at all"
	if got := redactBody(plain); got != plain {
		t.Errorf("redactBody mangled non-JSON body: %q", got)
	}
}

func TestSecureCompare(t *testing.T) {
	if !SecureCompare("abc123", "abc123") {
		t.Error("SecureCompare should return true for equal strings")
	}
	if SecureCompare("abc123", "abc124") {
		t.Error("SecureCompare should return false for differing strings of equal length")
	}
	if SecureCompare("abc", "abcd") {
		t.Error("SecureCompare should return false for differing-length inputs")
	}
	if SecureCompare("", "x") {
		t.Error("SecureCompare should return false for empty vs non-empty")
	}
}

func TestVerifyHash(t *testing.T) {
	const good = "correct-horse-battery-staple"
	// Same length as good but different content, to prove we compare content not length.
	const bad = "wrong-horse-battery-stapleX!"

	if len(good) != len(bad) {
		t.Fatalf("test setup: good and bad must be same length, got %d and %d", len(good), len(bad))
	}

	// Legacy sha1-stored hash must still verify (dual-read).
	sha1Stored := SHA1Hash(good)
	if !VerifyHash(sha1Stored, good) {
		t.Error("VerifyHash should accept a token stored with sha1")
	}
	if VerifyHash(sha1Stored, bad) {
		t.Error("VerifyHash should reject a wrong token against a sha1-stored hash")
	}

	// New sha256-stored hash must verify.
	sha256Stored := SHA256Hash(good)
	if !VerifyHash(sha256Stored, good) {
		t.Error("VerifyHash should accept a token stored with sha256")
	}
	if VerifyHash(sha256Stored, bad) {
		t.Error("VerifyHash should reject a wrong token against a sha256-stored hash")
	}

	// HashToken / HashAPIKey are the sha256 write path.
	if HashToken(good) != SHA256Hash(good) {
		t.Error("HashToken must use sha256")
	}
	if HashAPIKey(good) != SHA256Hash(good) {
		t.Error("HashAPIKey must use sha256")
	}
}
