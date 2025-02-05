package client

import (
	"fmt"
	"io/fs"

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/utils"
)

// Config represents certificate config.
type Config struct {
	Common      Common                  `yaml:"common"`
	Certificate []certstore.Certificate `yaml:"certificate"`
}

// Common represents common config.
type Common struct {
	CertDays        int         `yaml:"cert_days"`
	CertDaysRenewal int         `yaml:"cert_days_renewal"`
	CertDeploy      bool        `yaml:"certificate_deploy"`
	CertDir         string      `yaml:"certificate_dir"`
	CertDirPerm     fs.FileMode `yaml:"certificate_dir_perm"`
	CertFilePerm    fs.FileMode `yaml:"certificate_file_perm"`
	CertKeyFilePerm fs.FileMode `yaml:"certificate_keyfile_perm"`
	CertFileExt     string      `yaml:"certificate_file_ext"`
	CertKeyFileExt  string      `yaml:"certificate_keyfile_ext"`
	CmdEnabled      bool        `yaml:"cmd_enabled"`
	PreCmdRun       string      `yaml:"pre_cmd_run"`
	PreCmdTimeout   int         `yaml:"pre_cmd_timeout"`
	PostCmdRun      string      `yaml:"post_cmd_run"`
	PostCmdTimeout  int         `yaml:"post_cmd_timeout"`
	RevokeOnUpdate  bool        `yaml:"revoke_on_update"`
	RevokeOnDelete  bool        `yaml:"revoke_on_delete"`
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

	if s.Common.CertFileExt == "" {
		s.Common.CertFileExt = ".crt"
	}

	if s.Common.CertKeyFileExt == "" {
		s.Common.CertKeyFileExt = ".key"
	}

	// Validate unique issuer/domain name.
	domains := map[string]struct{}{}
	for _, cert := range s.Certificate {
		k := cert.Issuer + "/" + cert.Domain
		if _, ok := domains[k]; ok {
			return fmt.Errorf("found multiple certificate config with issuer '%s' and domain '%s'", cert.Issuer, cert.Domain)
		}
		domains[k] = struct{}{}
	}

	for _, cert := range s.Certificate {
		if cert.Labels != "" {
			err := utils.ValidateLabels(cert.Labels)
			if len(err) != 0 {
				return fmt.Errorf("%s", err)
			}
		}
	}

	return nil
}
