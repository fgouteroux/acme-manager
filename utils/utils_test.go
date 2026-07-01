package utils

import (
	"testing"
)

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
