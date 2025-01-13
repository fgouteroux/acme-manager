package client

import (
	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/config"
)

// Config represents certificate config.
type Config struct {
	Common      config.Common      `yaml:"common"`
	Certificate []cert.Certificate `yaml:"certificate"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(s)); err != nil {
		return err
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

	return nil
}
