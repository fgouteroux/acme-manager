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
	ChallengePrefix   = "challenge"
)

// =================== CERTIFICATES ===================

// GenerateCertificateKey creates a hierarchical key for certificates
func GenerateCertificateKey(owner, issuer, domain string) string {
	return fmt.Sprintf("%s/%s/%s/%s", CertificatePrefix, owner, issuer, domain)
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
	key := GenerateCertificateKey(cert.Owner, cert.Issuer, cert.Domain)

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
func (c *CertStore) GetCertificate(owner, issuer, domain string) (*models.Certificate, error) {
	key := GenerateCertificateKey(owner, issuer, domain)

	ctx := context.Background()
	cached, err := c.RingConfig.CertificateClient.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if cached == nil {
		return nil, fmt.Errorf("certificate '%s/%s/%s' not found", owner, issuer, domain)
	}

	cert := cached.(*models.Certificate)

	// Check for deletion
	if cert.DeletedAt > 0 {
		return nil, fmt.Errorf("certificate '%s/%s/%s' is pending deletion", owner, issuer, domain)
	}

	return cert, nil
}

// Delete certificate
func (c *CertStore) DeleteCertificate(owner, issuer, domain string) error {
	key := GenerateCertificateKey(owner, issuer, domain)

	ctx := context.Background()

	// First retrieve the existing certificate
	cached, err := c.RingConfig.CertificateClient.Get(ctx, key)
	if err != nil {
		return err
	}

	if cached == nil {
		return fmt.Errorf("certificate not found")
	}

	cert := cached.(*models.Certificate)

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

		cert := cached.(*models.Certificate)

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

		cert := cached.(*models.Certificate)

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
		return nil, fmt.Errorf("token id '%s' not found", tokenID)
	}

	token := cached.(*models.Token)

	// Check for deletion
	if token.DeletedAt > 0 {
		return nil, fmt.Errorf("token id '%s' is pending deletion", tokenID)
	}

	return token, nil
}

// Delete token
func (c *CertStore) DeleteToken(tokenID string) error {
	key := GenerateTokenKey(tokenID)

	ctx := context.Background()

	// Retrieve the existing token
	cached, err := c.RingConfig.TokenClient.Get(ctx, key)
	if err != nil {
		return err
	}

	if cached == nil {
		return fmt.Errorf("token not found")
	}

	token := cached.(*models.Token)

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

		token := cached.(*models.Token)
		tokens[key] = token
	}

	return tokens, nil
}

// =================== CHALLENGES ===================

// GenerateChallengeKey creates a hierarchical key for challenges
func GenerateChallengeKey(challengeID string) string {
	return fmt.Sprintf("%s/%s", ChallengePrefix, challengeID)
}

func (c *CertStore) ListChallengeKVRingKeys() ([]string, error) {
	return c.RingConfig.ChallengeClient.List(context.Background(), ChallengePrefix+"/")
}

// Store challenge
func (c *CertStore) PutChallenge(challengeID string, keyAuth string) error {
	key := GenerateChallengeKey(challengeID)

	challenge := &models.Challenge{
		KeyAuth:   keyAuth,
		UpdatedAt: timestamp.FromTime(time.Now()),
	}

	ctx := context.Background()
	err := c.RingConfig.ChallengeClient.CAS(ctx, key, func(_ interface{}) (interface{}, bool, error) {
		return challenge, true, nil
	})

	if err != nil {
		_ = level.Error(c.Logger).Log("msg", "Failed to store challenge", "key", key, "err", err)
	}
	return err
}

// Get challenge
func (c *CertStore) GetChallenge(challengeID string) (string, error) {
	key := GenerateChallengeKey(challengeID)

	ctx := context.Background()
	cached, err := c.RingConfig.ChallengeClient.Get(ctx, key)
	if err != nil {
		return "", err
	}

	if cached == nil {
		return "", fmt.Errorf("challenge id '%s' not found", challengeID)
	}

	challenge := cached.(*models.Challenge)

	// Check for deletion
	if challenge.DeletedAt > 0 {
		return "", fmt.Errorf("challenge id '%s' is pending deletion", challengeID)
	}

	return challenge.KeyAuth, nil
}

// Delete challenge
func (c *CertStore) DeleteChallenge(challengeID string) error {
	key := GenerateChallengeKey(challengeID)

	ctx := context.Background()
	return c.RingConfig.ChallengeClient.Delete(ctx, key)
}

// List all challenges
func (c *CertStore) ListAllChallenges() (map[string]string, error) {
	keys, err := c.ListChallengeKVRingKeys()
	if err != nil {
		return nil, err
	}

	challenges := make(map[string]string, len(keys))
	ctx := context.Background()

	for _, key := range keys {
		cached, err := c.RingConfig.ChallengeClient.Get(ctx, key)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get challenge", "key", key, "err", err)
			continue
		}

		if cached == nil {
			continue
		}

		challenge := cached.(*models.Challenge)
		if challenge.DeletedAt == 0 {
			challenges[key] = challenge.KeyAuth
		}
	}

	return challenges, nil
}
