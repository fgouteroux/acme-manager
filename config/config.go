package config

import (
	"golang.org/x/exp/maps"
)

var (
	SupportedIssuers []string
)

// Config represents config.
type Config struct {
	Common  Common            `yaml:"common"`
	Issuer  map[string]Issuer `yaml:"issuer"`
	Storage Storage           `yaml:"storage"`
}

// Common represents common config.
type Common struct {
	CertDeploy          bool   `yaml:"certificate_deploy"`
	CertDir             string `yaml:"certificate_dir"`
	RootPathAccount     string `yaml:"rootpath_account"`
	RootPathCertificate string `yaml:"rootpath_certificate"`
	CmdEnabled          bool   `yaml:"cmd_enabled"`
	CmdRun              string `yaml:"cmd_run"`
	CmdTimeout          int    `yaml:"cmd_timeout"`
	PruneCertificate    bool   `yaml:"prune_certificate"`
}

type Issuer struct {
	CADirURL     string `yaml:"ca_dir_url"`
	EAB          bool   `yaml:"eab"`
	KID          string `yaml:"kid,omitempty"`
	HMAC         string `yaml:"hmac,omitempty"`
	DNSChallenge string `yaml:"dns_challenge"`
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
	SecretPrefix string `yaml:"secret_prefix"`
	MountPath    string `yaml:"mount_path"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	SupportedIssuers = maps.Keys(s.Issuer)

	return nil
}
