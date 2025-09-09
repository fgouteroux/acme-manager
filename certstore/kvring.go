package certstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"strings"

	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/memcache"
	"github.com/fgouteroux/acme_manager/ring"

	"github.com/prometheus/prometheus/model/timestamp"
)

// Key prefixes
const (
	CertificatePrefix = "certificate"
	TokenPrefix       = "token"
	ChallengePrefix   = "challenge"
)

var localCache = memcache.NewLocalCache()


func (c *CertStore) GetKVRing(key string, isLeader bool) (string, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	var data string

	if isLeader {
		if cached, found := localCache.Get(key); found {
			data = cached.Value.(string)
		}
	} else {
		ctx := context.Background()
		cached, err := c.RingConfig.DataClient.Get(ctx, key)
		if err != nil {
			return data, err
		}

		if cached != nil {
			data = cached.(*ring.Data).Content
		}
	}

	return data, nil
}

func (c *CertStore) PutKVRing(key string, data interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	_ = level.Debug(c.Logger).Log("msg", fmt.Sprintf("Updating kv store key '%s'", key))

	content, _ := json.Marshal(data)
	c.updateKV(key, string(content))
	_ = level.Debug(c.Logger).Log("msg", fmt.Sprintf("Updated kv store key '%s'", key))
}

func (c *CertStore) updateKV(key, content string) {
	// update local cache
	localCache.Set(key, content)

	updatedAt := time.Now()
	data := &ring.Data{
		Content:   content,
		UpdatedAt: timestamp.FromTime(updatedAt),
	}

	ctx := context.Background()
	err := c.RingConfig.DataClient.CAS(ctx, key, func(_ interface{}) (out interface{}, retry bool, err error) {
		return data, true, nil
	})

	if err != nil {
		_ = level.Error(c.Logger).Log("msg", "Failed to update KV store after retries", "key", key, "err", err)
	}
}

// GenerateCertificateKey creates a hierarchical key for certificates
func GenerateCertificateKey(owner, issuer, domain string) string {
	return fmt.Sprintf("%s/%s/%s/%s", CertificatePrefix, owner, issuer, domain)
}

// GenerateTokenKey creates a hierarchical key for tokens
func GenerateTokenKey(tokenID string) string {
	return fmt.Sprintf("%s/%s", TokenPrefix, tokenID)
}

// GenerateChallengeKey creates a hierarchical key for challenges
func GenerateChallengeKey(challengeID string) string {
	return fmt.Sprintf("%s/%s", ChallengePrefix, challengeID)
}

// ParseTokenKey extracts components from a token key
func ParseTokenKey(key string) (tokenID string, err error) {
	parts := strings.Split(key, "/")
	if len(parts) != 2 || parts[0] != TokenPrefix {
		return "", fmt.Errorf("invalid token key format: %s", key)
	}
	return parts[1], nil
}

// GetCertificateKeysForOwner generates a prefix to list all certificates for an owner
func GetCertificateKeysForOwner(owner string) string {
	return fmt.Sprintf("%s/%s/", CertificatePrefix, owner)
}

// GetCertificateKeysForOwnerAndIssuer generates a prefix to list certificates for owner+issuer
func GetCertificateKeysForOwnerAndIssuer(owner, issuer string) string {
	return fmt.Sprintf("%s/%s/%s/", CertificatePrefix, owner, issuer)
}

// GetTokenKeysForOwner generates a prefix to list all tokens for an owner
func GetTokenKeysForOwner(owner string) string {
	return fmt.Sprintf("%s/%s/", TokenPrefix, owner)
}

// Store individual certificate
func (c *CertStore) PutCertificate(cert Certificate) error {
	key := GenerateCertificateKey(cert.Owner, cert.Issuer, cert.Domain)
	c.PutKVRing(key, cert)
	return nil
}

// Get individual certificate
func (c *CertStore) GetCertificate(owner, issuer, domain string, isLeader bool) (Certificate, error) {
	var cert Certificate
	key := GenerateCertificateKey(owner, issuer, domain)
	
	content, err := c.GetKVRing(key, isLeader)
	if err != nil {
		return cert, err
	}
	
	if content == "" {
		return cert, fmt.Errorf("certificate '%s/%s' not found", issuer,domain)
	}
	
	err = json.Unmarshal([]byte(content), &cert)
	return cert, err
}

// Delete individual certificate
func (c *CertStore) DeleteCertificate(owner, issuer, domain string) error {
	key := GenerateCertificateKey(owner, issuer, domain)
	return c.DeleteKVRing(key)
}

// List all certificates for an owner
func (c *CertStore) ListCertificatesForOwner(owner string, isLeader bool) ([]Certificate, error) {
	prefix := GetCertificateKeysForOwner(owner)
	keys, err := c.ListKVRingKeys(prefix, isLeader)
	if err != nil {
		return nil, err
	}
	
	var certificates []Certificate
	for _, key := range keys {
		content, err := c.GetKVRing(key, isLeader)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get certificate", "key", key, "err", err)
			continue
		}
		
		var cert Certificate
		if err := json.Unmarshal([]byte(content), &cert); err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to unmarshal certificate", "key", key, "err", err)
			continue
		}
		
		certificates = append(certificates, cert)
	}
	
	return certificates, nil
}

// List all certificates (for backward compatibility and monitoring)
func (c *CertStore) ListAllCertificates(isLeader bool) (map[string]Certificate, error) {
	keys, err := c.ListKVRingKeys(CertificatePrefix+"/", isLeader)
	if err != nil {
		return nil, err
	}
	
	certificates := make(map[string]Certificate, len(keys))
	for _, key := range keys {
		content, err := c.GetKVRing(key, isLeader)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get certificate", "key", key, "err", err)
			continue
		}
		
		var cert Certificate
		if err := json.Unmarshal([]byte(content), &cert); err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to unmarshal certificate", "key", key, "err", err)
			continue
		}
		
		certificates[key] = cert
	}
	
	return certificates, nil
}

// List all tokens (for backward compatibility and monitoring)
func (c *CertStore) ListAllTokens(isLeader bool) (map[string]Token, error) {
	keys, err := c.ListKVRingKeys(TokenPrefix+"/", isLeader)
	if err != nil {
		return nil, err
	}
	
	tokens := make(map[string]Token, len(keys))
	for _, key := range keys {
		content, err := c.GetKVRing(key, isLeader)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get token", "key", key, "err", err)
			continue
		}
		
		var token Token
		if err := json.Unmarshal([]byte(content), &token); err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to unmarshal token", "key", key, "err", err)
			continue
		}
		
		tokens[key] = token
	}
	
	return tokens, nil
}

// List all challenges (for backward compatibility and monitoring)
func (c *CertStore) ListAllChallenges(isLeader bool) (map[string]string, error) {
	keys, err := c.ListKVRingKeys(ChallengePrefix+"/", isLeader)
	if err != nil {
		return nil, err
	}
	
	challenges := make(map[string]string, len(keys))
	for _, key := range keys {
		content, err := c.GetKVRing(key, isLeader)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get challenge", "key", key, "err", err)
			continue
		}
		
		challenges[key] = content
	}
	
	return challenges, nil
}

// Similar methods for tokens
func (c *CertStore) PutToken(tokenID string, token Token) error {
	key := GenerateTokenKey(tokenID)
	c.PutKVRing(key, token)
	return nil
}

func (c *CertStore) GetToken(tokenID string, isLeader bool) (Token, error) {
	var token Token
	key := GenerateTokenKey(tokenID)

	content, err := c.GetKVRing(key, isLeader)
	if err != nil {
		return token, err
	}
	
	if content == "" {
		return token, fmt.Errorf("token id '%s' not found", tokenID)
	}
	
	err = json.Unmarshal([]byte(content), &token)
	return token, err
}

func (c *CertStore) DeleteToken(tokenID string) error {
	key := GenerateTokenKey(tokenID)
	return c.DeleteKVRing(key)
}

func (c *CertStore) ListTokensForOwner(owner string, isLeader bool) (map[string]Token, error) {
	prefix := GetTokenKeysForOwner(owner)
	keys, err := c.ListKVRingKeys(prefix, isLeader)
	if err != nil {
		return nil, err
	}
	
	tokens := make(map[string]Token)
	for _, key := range keys {
		content, err := c.GetKVRing(key, isLeader)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to get token", "key", key, "err", err)
			continue
		}
		
		var token Token
		if err := json.Unmarshal([]byte(content), &token); err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to unmarshal token", "key", key, "err", err)
			continue
		}
		
		// Extract tokenID from key
		tokenID, err := ParseTokenKey(key)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to parse token key", "key", key, "err", err)
			continue
		}
		
		tokens[tokenID] = token
	}
	
	return tokens, nil
}

// Similar methods for challenges
func (c *CertStore) PutChallenge(challengeID string, challenge string) error {
	key := GenerateChallengeKey(challengeID)
	c.PutKVRing(key, challenge)
	return nil
}

func (c *CertStore) GetChallenge(challengeID string, isLeader bool) (string, error) {
	key := GenerateChallengeKey(challengeID)
	data, err := c.GetKVRing(key, isLeader)
	if err != nil {
		return "", err
	}
	
	if data == "" {
		return data, fmt.Errorf("challenge id '%s' not found", challengeID)
	}
	return data, nil
}

func (c *CertStore) DeleteChallenge(challengeID string) error {
	key := GenerateChallengeKey(challengeID)
	return c.DeleteKVRing(key)
}

// Add methods you'll need for key listing and deletion
func (c *CertStore) ListKVRingKeys(prefix string, isLeader bool) ([]string, error) {
	// This method needs to be implemented based on your KV store backend
	// For etcd/consul, you'd use prefix listing
	// Implementation depends on your ring.DataClient interface
	ctx := context.Background()
	
	if isLeader {
		// For leader, might need to scan local cache
		return c.listKeysFromCache(prefix), nil
	}
	// For non-leader, use the ring client to list keys
	return c.RingConfig.DataClient.List(ctx, prefix)
}

func (c *CertStore) listKeysFromCache(prefix string) []string {
	allKeys := localCache.GetAllKeys()
	var matchingKeys []string
	
	for _, key := range allKeys {
		if strings.HasPrefix(key, prefix) {
			matchingKeys = append(matchingKeys, key)
		}
	}
	
	return matchingKeys
}

func (c *CertStore) DeleteKVRing(key string) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	
	// Remove from local cache
	localCache.Del(key)

	fmt.Printf("Deleted key %s", key)
	
	// Remove from ring
	ctx := context.Background()
	return c.RingConfig.DataClient.Delete(ctx, key)
}
