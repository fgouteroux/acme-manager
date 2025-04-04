package config

import (
	"fmt"

	"github.com/fgouteroux/acme_manager/utils"

	"golang.org/x/exp/maps"
)

var (
	SupportedIssuers []string
	GlobalConfig     Config
)

// Config represents config.
type Config struct {
	Common  Common            `yaml:"common"`
	Issuer  map[string]Issuer `yaml:"issuer"`
	Storage Storage           `yaml:"storage"`
}

// Common represents common config.
type Common struct {
	APIKeyHash          string `yaml:"api_key_hash"`
	CertDaysRenewal     string `yaml:"cert_days_renewal"`
	RootPathAccount     string `yaml:"rootpath_account"`
	RootPathCertificate string `yaml:"rootpath_certificate"`
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

	for issuer, issuerConf := range s.Issuer {
		if issuerConf.DNSChallenge != "" && issuerConf.HTTPChallenge != "" {
			return fmt.Errorf("Invalid config in '%s' issuer, 'dns_challenge' and 'http_challenge' are mutually exclusive", issuer)
		}

		if issuerConf.DNSChallenge == "" && issuerConf.HTTPChallenge == "" {
			return fmt.Errorf("Invalid config in '%s' issuer, 'dns_challenge' or 'http_challenge' must be set", issuer)
		}

		if issuerConf.OverallRequestLimit == 0 {
			issuerConf.OverallRequestLimit = 18
		}

		if issuerConf.CertificateTimeout == 0 {
			issuerConf.CertificateTimeout = 30
		}
	}

	SupportedIssuers = maps.Keys(s.Issuer)

	return nil
}
