package certstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/model/timestamp"

	"github.com/fgouteroux/acme-manager/models"
)

// Key prefixes
const (
	CertificatePrefix = "certificate"
	TokenPrefix       = "token"
	RateLimitPrefix   = "ratelimit"
)

// =================== CERTIFICATES ===================

// GenerateCertificatePath builds a slash-separated path.
// Named certs (name != ""): prefix/owner/name  — issuer and domain are in the value, not the key.
// Unnamed certs:            prefix/owner/issuer/domain (backward compatible).
func GenerateCertificatePath(prefix, owner, issuer, name, domain string) string {
	if name != "" {
		return fmt.Sprintf("%s/%s/%s", prefix, owner, name)
	}
	return fmt.Sprintf("%s/%s/%s/%s", prefix, owner, issuer, domain)
}

// GenerateCertificateKey creates a hierarchical key for certificates in the KV ring.
func GenerateCertificateKey(owner, issuer, name, domain string) string {
	return GenerateCertificatePath(CertificatePrefix, owner, issuer, name, domain)
}

// GetCertificateKeysForOwner generates a prefix to list all certificates for an owner
func GetCertificateKeysForOwner(owner string) string {
	return fmt.Sprintf("%s/%s/", CertificatePrefix, owner)
}

// GetCertificateKeysForOwnerAndIssuer generates a prefix to list certificates for owner+issuer
func GetCertificateKeysForOwnerAndIssuer(owner, issuer string) string {
	return fmt.Sprintf("%s/%s/%s/", CertificatePrefix, owner, issuer)
}

func (c *CertStore) ListCertificateKVRingKeys(prefix string) ([]string, error) {
	return c.RingConfig.CertificateClient.List(context.Background(), prefix)
}

// Store certificate
func (c *CertStore) PutCertificate(cert *models.Certificate) error {
	key := GenerateCertificateKey(cert.Owner, cert.Issuer, cert.Name, cert.Domain)

	// Update the timestamp
	cert.UpdatedAt = timestamp.FromTime(time.Now())

	ctx := context.Background()
	err := c.RingConfig.CertificateClient.CAS(ctx, key, func(_ interface{}) (interface{}, bool, error) {
		return cert, true, nil
	})

	if err != nil {
		_ = level.Error(c.Logger).Log("msg", "Failed to store certificate", "key", key, "err", err)
	}
	return err
}

// Get certificate
func (c *CertStore) GetCertificate(owner, issuer, name, domain string) (*models.Certificate, error) {
	key := GenerateCertificateKey(owner, issuer, name, domain)

	ctx := context.Background()
	cached, err := c.RingConfig.CertificateClient.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if cached == nil {
		return nil, fmt.Errorf("certificate '%s' %w", key, ErrNotFound)
	}

	cert, ok := cached.(*models.Certificate)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T for certificate key %s", cached, key)
	}

	// Check for deletion
	if cert.DeletedAt > 0 {
		return nil, fmt.Errorf("certificate '%s' is %w", key, ErrPendingDeletion)
	}

	return cert, nil
}

// Delete certificate marks the entry deleted (CAS sets DeletedAt) and then
// Deletes it from the ring. These two steps are not atomic: if the process dies
// between them, a tombstone (DeletedAt > 0) lingers and GetCertificate reports
// "pending deletion" (409) until the periodic reaper (ReapDeletedRingEntries)
// removes it. This is an accepted eventual-consistency window.
func (c *CertStore) DeleteCertificate(owner, issuer, name, domain string) error {
	key := GenerateCertificateKey(owner, issuer, name, domain)

	ctx := context.Background()

	// First retrieve the existing certificate
	cached, err := c.RingConfig.CertificateClient.Get(ctx, key)
	if err != nil {
		return err
	}

	if cached == nil {
		return fmt.Errorf("certificate '%s' %w", key, ErrNotFound)
	}

	cert, ok := cached.(*models.Certificate)
	if !ok {
		return fmt.Errorf("unexpected type %T for certificate key %s", cached, key)
	}

	// Mark as deleted
	cert.DeletedAt = timestamp.FromTime(time.Now())
	cert.UpdatedAt = timestamp.FromTime(time.Now())

	// Notify the deletion
	err = c.RingConfig.CertificateClient.CAS(ctx, key, func(_ interface{}) (interface{}, bool, error) {
		return cert, true, nil
	})

	if err != nil {
		_ = level.Error(c.Logger).Log("msg", "Failed to mark certificate for deletion", "key", key, "err", err)
		return err
	}

	// Delete from ring
	return c.RingConfig.CertificateClient.Delete(ctx, key)
}

// List all certificates for an owner
func (c *CertStore) ListCertificatesForOwner(owner string) ([]*models.Certificate, error) {
	prefix := GetCertificateKeysForOwner(owner)
	keys, err := c.ListCertificateKVRingKeys(prefix)
	if err != nil {
		return nil, err
	}

	var certificates []*models.Certificate
	ctx := context.Background()

	for _, key := range keys {
		cached, err := c.RingConfig.CertificateClient.Get(ctx, key)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get certificate", "key", key, "err", err)
			continue
		}

		if cached == nil {
			continue
		}

		cert, ok := cached.(*models.Certificate)
		if !ok {
			_ = level.Error(c.Logger).Log("msg", "unexpected type for certificate", "key", key, "type", fmt.Sprintf("%T", cached))
			continue
		}

		// Skip deleted certificates (pending deletion)
		if cert.DeletedAt == 0 {
			certificates = append(certificates, cert)
		}
	}

	return certificates, nil
}

// List all certificates
func (c *CertStore) ListAllCertificates() (map[string]*models.Certificate, error) {
	keys, err := c.ListCertificateKVRingKeys(CertificatePrefix + "/")
	if err != nil {
		return nil, err
	}

	certificates := make(map[string]*models.Certificate, len(keys))
	ctx := context.Background()

	for _, key := range keys {
		cached, err := c.RingConfig.CertificateClient.Get(ctx, key)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get certificate", "key", key, "err", err)
			continue
		}

		if cached == nil {
			continue
		}

		cert, ok := cached.(*models.Certificate)
		if !ok {
			_ = level.Error(c.Logger).Log("msg", "unexpected type for certificate", "key", key, "type", fmt.Sprintf("%T", cached))
			continue
		}

		if cert.DeletedAt == 0 {
			certificates[key] = cert
		}
	}

	return certificates, nil
}

// =================== TOKENS ===================

// GenerateTokenKey creates a hierarchical key for tokens
func GenerateTokenKey(tokenID string) string {
	return fmt.Sprintf("%s/%s", TokenPrefix, tokenID)
}

// ParseTokenKey extracts components from a token key
func ParseTokenKey(key string) (tokenID string, err error) {
	parts := strings.Split(key, "/")
	if len(parts) != 2 || parts[0] != TokenPrefix {
		return "", fmt.Errorf("invalid token key format: %s", key)
	}
	return parts[1], nil
}

// GetTokenKeysForOwner generates a prefix to list all tokens for an owner
func GetTokenKeysForOwner(owner string) string {
	return fmt.Sprintf("%s/%s/", TokenPrefix, owner)
}

func (c *CertStore) ListTokenKVRingKeys() ([]string, error) {
	return c.RingConfig.TokenClient.List(context.Background(), TokenPrefix+"/")
}

// Store token
func (c *CertStore) PutToken(tokenID string, token *models.Token) error {
	key := GenerateTokenKey(tokenID)

	// Update the timestamp
	token.UpdatedAt = timestamp.FromTime(time.Now())

	ctx := context.Background()
	err := c.RingConfig.TokenClient.CAS(ctx, key, func(_ interface{}) (interface{}, bool, error) {
		return token, true, nil
	})

	if err != nil {
		_ = level.Error(c.Logger).Log("msg", "Failed to store token", "key", key, "err", err)
	}
	return err
}

// Get token
func (c *CertStore) GetToken(tokenID string) (*models.Token, error) {
	key := GenerateTokenKey(tokenID)

	ctx := context.Background()
	cached, err := c.RingConfig.TokenClient.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if cached == nil {
		return nil, fmt.Errorf("token id '%s' %w", tokenID, ErrNotFound)
	}

	token, ok := cached.(*models.Token)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T for token key %s", cached, key)
	}

	// Check for deletion
	if token.DeletedAt > 0 {
		return nil, fmt.Errorf("token id '%s' is %w", tokenID, ErrPendingDeletion)
	}

	return token, nil
}

// Delete token marks the entry deleted (CAS sets DeletedAt) and then Deletes it
// from the ring. As with DeleteCertificate these steps are not atomic: a crash
// in between leaves a tombstone (DeletedAt > 0) that GetToken reports as
// "pending deletion" (409) until the periodic reaper (ReapDeletedRingEntries)
// removes it. This is an accepted eventual-consistency window.
func (c *CertStore) DeleteToken(tokenID string) error {
	key := GenerateTokenKey(tokenID)

	ctx := context.Background()

	// Retrieve the existing token
	cached, err := c.RingConfig.TokenClient.Get(ctx, key)
	if err != nil {
		return err
	}

	if cached == nil {
		return fmt.Errorf("token id '%s' %w", tokenID, ErrNotFound)
	}

	token, ok := cached.(*models.Token)
	if !ok {
		return fmt.Errorf("unexpected type %T for token key %s", cached, key)
	}

	// Mark as deleted
	token.DeletedAt = timestamp.FromTime(time.Now())
	token.UpdatedAt = timestamp.FromTime(time.Now())

	// Update
	err = c.RingConfig.TokenClient.CAS(ctx, key, func(_ interface{}) (interface{}, bool, error) {
		return token, true, nil
	})

	if err != nil {
		return err
	}

	// Delete from ring
	return c.RingConfig.TokenClient.Delete(ctx, key)
}

// List all tokens
func (c *CertStore) ListAllTokens() (map[string]*models.Token, error) {
	keys, err := c.ListTokenKVRingKeys()
	if err != nil {
		return nil, err
	}

	tokens := make(map[string]*models.Token, len(keys))
	ctx := context.Background()

	for _, key := range keys {
		cached, err := c.RingConfig.TokenClient.Get(ctx, key)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get token", "key", key, "err", err)
			continue
		}

		if cached == nil {
			continue
		}

		token, ok := cached.(*models.Token)
		if !ok {
			_ = level.Error(c.Logger).Log("msg", "unexpected type for token", "key", key, "type", fmt.Sprintf("%T", cached))
			continue
		}
		tokens[key] = token
	}

	return tokens, nil
}

// =================== RATE LIMITS ===================

// GenerateRateLimitKey creates a hierarchical key for rate limits.
// Named certs use name as the stable identifier (issuer and domain excluded); unnamed certs use issuer+domain.
func GenerateRateLimitKey(owner, issuer, name, domain string) string {
	if name != "" {
		return fmt.Sprintf("%s/%s/%s", RateLimitPrefix, owner, name)
	}
	return fmt.Sprintf("%s/%s/%s/%s", RateLimitPrefix, owner, issuer, domain)
}

func (c *CertStore) ListRateLimitKVRingKeys(prefix string) ([]string, error) {
	return c.RingConfig.RateLimitClient.List(context.Background(), prefix)
}

// Store rate limit
func (c *CertStore) PutRateLimit(rateLimit *models.RateLimit, name string) error {
	key := GenerateRateLimitKey(rateLimit.Owner, rateLimit.Issuer, name, rateLimit.Domain)

	// Update the timestamp
	rateLimit.UpdatedAt = timestamp.FromTime(time.Now())

	ctx := context.Background()
	err := c.RingConfig.RateLimitClient.CAS(ctx, key, func(_ interface{}) (interface{}, bool, error) {
		return rateLimit, true, nil
	})

	if err != nil {
		_ = level.Error(c.Logger).Log("msg", "Failed to store rate limit", "key", key, "err", err)
	}
	return err
}

// Get rate limit
func (c *CertStore) GetRateLimit(owner, issuer, name, domain string) (*models.RateLimit, error) {
	key := GenerateRateLimitKey(owner, issuer, name, domain)

	ctx := context.Background()
	cached, err := c.RingConfig.RateLimitClient.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if cached == nil {
		return nil, nil // Not found is not an error for rate limits
	}

	rateLimit, ok := cached.(*models.RateLimit)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T for rate limit key %s", cached, key)
	}

	// Check for deletion
	if rateLimit.DeletedAt > 0 {
		return nil, nil
	}

	return rateLimit, nil
}

// Delete rate limit
func (c *CertStore) DeleteRateLimit(owner, issuer, name, domain string) error {
	key := GenerateRateLimitKey(owner, issuer, name, domain)

	ctx := context.Background()
	return c.RingConfig.RateLimitClient.Delete(ctx, key)
}

// DeleteRateLimitByKey deletes a rate limit entry by its full KV key.
// Used when the key is already known (e.g. from ListAllRateLimits iteration).
func (c *CertStore) DeleteRateLimitByKey(key string) error {
	ctx := context.Background()
	return c.RingConfig.RateLimitClient.Delete(ctx, key)
}

// List all rate limits
func (c *CertStore) ListAllRateLimits() (map[string]*models.RateLimit, error) {
	keys, err := c.ListRateLimitKVRingKeys(RateLimitPrefix + "/")
	if err != nil {
		return nil, err
	}

	rateLimits := make(map[string]*models.RateLimit, len(keys))
	ctx := context.Background()

	for _, key := range keys {
		cached, err := c.RingConfig.RateLimitClient.Get(ctx, key)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get rate limit", "key", key, "err", err)
			continue
		}

		if cached == nil {
			continue
		}

		rateLimit, ok := cached.(*models.RateLimit)
		if !ok {
			_ = level.Error(c.Logger).Log("msg", "unexpected type for rate limit", "key", key, "type", fmt.Sprintf("%T", cached))
			continue
		}
		if rateLimit.DeletedAt == 0 {
			rateLimits[key] = rateLimit
		}
	}

	return rateLimits, nil
}
