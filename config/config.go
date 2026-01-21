package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fgouteroux/acme-manager/utils"

	"golang.org/x/exp/maps"
)

var (
	SupportedIssuers []string
	GlobalConfig     Config
	SecuredPlugins   []string
)

// Config represents config.
type Config struct {
	Common  Common            `yaml:"common"`
	Issuer  map[string]Issuer `yaml:"issuer"`
	Storage Storage           `yaml:"storage"`
}

// Plugin represents plugin.
type Plugin struct {
	Name     string            `yaml:"name"`
	Path     string            `yaml:"path"`
	Checksum string            `yaml:"checksum"`
	Timeout  int               `yaml:"timeout"`
	Env      map[string]string `yaml:"env"`
}

// Common represents common config.
type Common struct {
	APIKeyHash                string   `yaml:"api_key_hash"`
	CertDaysRenewal           string   `yaml:"cert_days_renewal"`
	RootPathAccount           string   `yaml:"rootpath_account"`
	RootPathCertificate       string   `yaml:"rootpath_certificate"`
	Plugins                   []Plugin `yaml:"plugins"`
	HTTPClientRetryMax        int      `yaml:"http_client_retry_max"`
	HTTPClientRetryWaitMin    int      `yaml:"http_client_retry_wait_min"`
	HTTPClientRetryWaitMax    int      `yaml:"http_client_retry_wait_max"`
	HTTPClientRetryStatusCode []int    `yaml:"http_client_retry_status_code"`
	HTTPClientDebug           bool     `yaml:"http_client_debug"`
	// Rate limiting configuration
	RateLimitEnabled     bool   `yaml:"rate_limit_enabled"`      // Enable rate limiting (default: false)
	RateLimitWindow      string `yaml:"rate_limit_window"`       // Time window for rate limiting (default: "1h")
	RateLimitMaxRequests int    `yaml:"rate_limit_max_requests"` // Max requests per window (default: 1)
}

type Issuer struct {
	Contact             string `yaml:"contact"`
	CADirURL            string `yaml:"ca_dir_url"`
	EAB                 bool   `yaml:"eab"`
	KID                 string `yaml:"kid,omitempty"`
	HMAC                string `yaml:"hmac,omitempty"`
	DNSChallenge        string `yaml:"dns_challenge"`
	HTTPChallenge       string `yaml:"http_challenge"`
	HTTPChallengeCfg    string `yaml:"http_challenge_config"`
	OverallRequestLimit int    `yaml:"overall_request_limit"`
	CertificateTimeout  int    `yaml:"certificate_timeout"`
	Unregister          bool   `yaml:"unregister"`
}

// Storage represents storage config.
type Storage struct {
	Vault Vault `yaml:"vault"`
}

// Vault represents vault storage config.
type Vault struct {
	RoleID       string `yaml:"role_id"`
	SecretID     string `yaml:"secret_id"`
	URL          string `yaml:"url"`
	SecretEngine string `yaml:"secret_engine"`
	CertPrefix   string `yaml:"certificate_prefix"`
	TokenPrefix  string `yaml:"token_prefix"`
	MountPath    string `yaml:"mount_path"`
	RetryMax     int    `yaml:"retry_max"`
	RetryWaitMin int    `yaml:"retry_wait_min"`
	RetryWaitMax int    `yaml:"retry_wait_max"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if s.Common.CertDaysRenewal == "" {
		s.Common.CertDaysRenewal = "20-30"
	} else if _, _, err := utils.ValidateRenewalDays(s.Common.CertDaysRenewal); err != nil {
		return err
	}

	// Rate limiting defaults and validation
	if s.Common.RateLimitEnabled {
		if s.Common.RateLimitWindow == "" {
			s.Common.RateLimitWindow = "1h"
		}
		if _, err := time.ParseDuration(s.Common.RateLimitWindow); err != nil {
			return fmt.Errorf("invalid rate_limit_window '%s': %v", s.Common.RateLimitWindow, err)
		}
		if s.Common.RateLimitMaxRequests == 0 {
			s.Common.RateLimitMaxRequests = 1
		}
		if s.Common.RateLimitMaxRequests < 0 {
			return fmt.Errorf("rate_limit_max_requests must be positive, got %d", s.Common.RateLimitMaxRequests)
		}
	}

	for issuer, issuerConf := range s.Issuer {
		if issuerConf.DNSChallenge != "" && issuerConf.HTTPChallenge != "" {
			return fmt.Errorf("invalid config in '%s' issuer, 'dns_challenge' and 'http_challenge' are mutually exclusive", issuer)
		}

		if issuerConf.DNSChallenge == "" && issuerConf.HTTPChallenge == "" {
			return fmt.Errorf("invalid config in '%s' issuer, 'dns_challenge' or 'http_challenge' must be set", issuer)
		}

		if issuerConf.OverallRequestLimit == 0 {
			issuerConf.OverallRequestLimit = 18
		}

		if issuerConf.CertificateTimeout == 0 {
			issuerConf.CertificateTimeout = 30
		}
	}

	var checkedPlugins []string
	for _, item := range s.Common.Plugins {
		if item.Checksum != "" {
			// Open the file
			file, err := os.Open(item.Path)
			if err != nil {
				return fmt.Errorf("error opening plugin '%s': %v", item.Name, err)
			}
			defer file.Close()

			// Create a new SHA-256 hash
			hash := sha256.New()

			// Copy the file contents to the hash
			if _, err := io.Copy(hash, file); err != nil {
				return fmt.Errorf("error reading plugin '%s': %v", item.Name, err)
			}

			// Get the checksum as a byte slice
			checksum := hash.Sum(nil)

			// Convert the checksum to a hexadecimal string
			checksumHex := hex.EncodeToString(checksum)

			if item.Checksum != checksumHex {
				return fmt.Errorf("plugin '%s' checksum '%s' doesn't match current config checksum '%s", item.Name, checksumHex, item.Checksum)
			}
			checkedPlugins = append(checkedPlugins, item.Name)
		}
	}
	SecuredPlugins = checkedPlugins

	SupportedIssuers = maps.Keys(s.Issuer)

	return nil
}
