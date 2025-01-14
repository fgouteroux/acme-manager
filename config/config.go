package config

import (
	"fmt"
	"golang.org/x/exp/maps"
	"io/fs"
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
	APIKeyHash          string      `yaml:"api_key_hash"`
	CertDays            int         `yaml:"cert_days"`
	CertDaysRenewal     int         `yaml:"cert_days_renewal"`
	CertDeploy          bool        `yaml:"certificate_deploy"`
	CertDir             string      `yaml:"certificate_dir"`
	CertDirPerm         fs.FileMode `yaml:"certificate_dir_perm"`
	CertFilePerm        fs.FileMode `yaml:"certificate_file_perm"`
	CertKeyFilePerm     fs.FileMode `yaml:"certificate_keyfile_perm"`
	RootPathAccount     string      `yaml:"rootpath_account"`
	RootPathCertificate string      `yaml:"rootpath_certificate"`
	CmdEnabled          bool        `yaml:"cmd_enabled"`
	CmdRun              string      `yaml:"cmd_run"`
	CmdTimeout          int         `yaml:"cmd_timeout"`
	PruneCertificate    bool        `yaml:"prune_certificate"`
}

type Issuer struct {
	CADirURL         string `yaml:"ca_dir_url"`
	EAB              bool   `yaml:"eab"`
	KID              string `yaml:"kid,omitempty"`
	HMAC             string `yaml:"hmac,omitempty"`
	DNSChallenge     string `yaml:"dns_challenge"`
	HTTPChallenge    string `yaml:"http_challenge"`
	HTTPChallengeCfg string `yaml:"http_challenge_config"`
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

	if s.Common.CertDays == 0 {
		s.Common.CertDays = 90
	}

	if s.Common.CertDaysRenewal == 0 {
		s.Common.CertDaysRenewal = 30
	}

	if s.Common.CertDirPerm == 0 {
		s.Common.CertDirPerm = 0700
	}

	if s.Common.CertFilePerm == 0 {
		s.Common.CertFilePerm = 0600
	}

	if s.Common.CertKeyFilePerm == 0 {
		s.Common.CertKeyFilePerm = 0600
	}

	for issuer, issuerConf := range s.Issuer {
		if issuerConf.DNSChallenge != "" && issuerConf.HTTPChallenge != "" {
			return fmt.Errorf("Invalid config in '%s' issuer, 'dns_challenge' and 'http_challenge' are mutually exclusive", issuer)
		}

		if issuerConf.DNSChallenge == "" && issuerConf.HTTPChallenge == "" {
			return fmt.Errorf("Invalid config in '%s' issuer, 'dns_challenge' or 'http_challenge' must be set", issuer)
		}
	}

	SupportedIssuers = maps.Keys(s.Issuer)

	return nil
}
