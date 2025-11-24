package client

import (
	"fmt"
	"io/fs"

	"github.com/prometheus/common/model"

	cfg "github.com/fgouteroux/acme-manager/config"
	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/utils"
)

type CertConfig struct {
	Domain        string `yaml:"domain"`
	Issuer        string `yaml:"issuer"`
	Bundle        bool   `yaml:"bundle,omitempty"`
	San           string `yaml:"san,omitempty"`
	Days          int32  `yaml:"days,omitempty"`
	RenewalDays   string `yaml:"renewal_days,omitempty"`
	DNSChallenge  string `yaml:"dns_challenge,omitempty"`
	HTTPChallenge string `yaml:"http_challenge,omitempty"`
	KeyType       string `yaml:"key_type,omitempty"`
	Labels        string `yaml:"labels,omitempty"`
}

// Convert to models.Certificate
func (cc CertConfig) ToModelsCertificate() models.Certificate {
	return models.Certificate{
		Domain:        cc.Domain,
		Issuer:        cc.Issuer,
		Bundle:        cc.Bundle,
		San:           cc.San,
		Days:          cc.Days,
		RenewalDays:   cc.RenewalDays,
		DnsChallenge:  cc.DNSChallenge,
		HttpChallenge: cc.HTTPChallenge,
		KeyType:       cc.KeyType,
		Labels:        cc.Labels,
	}
}

// Config represents certificate config.
type Config struct {
	Common      Common       `yaml:"common"`
	Certificate []CertConfig `yaml:"certificate"`
	Storage     cfg.Storage  `yaml:"storage"`
}

// Common represents common config.
type Common struct {
	CertDays          int         `yaml:"cert_days"`
	CertDaysRenewal   string      `yaml:"cert_days_renewal"`
	CertBackup        bool        `yaml:"certificate_backup"`
	CertDeploy        bool        `yaml:"certificate_deploy"`
	CertDir           string      `yaml:"certificate_dir"`
	CertDirPerm       fs.FileMode `yaml:"certificate_dir_perm"`
	CertFilePerm      fs.FileMode `yaml:"certificate_file_perm"`
	CertKeyFilePerm   fs.FileMode `yaml:"certificate_keyfile_perm"`
	CertFileExt       string      `yaml:"certificate_file_ext"`
	CertKeyFileExt    string      `yaml:"certificate_keyfile_ext"`
	CertKeyFileNoGen  bool        `yaml:"certificate_keyfile_no_generate"`
	CertTimeout       int         `yaml:"certificate_timeout"`
	CmdEnabled        bool        `yaml:"cmd_enabled"`
	PreCmdRun         string      `yaml:"pre_cmd_run"`
	PreCmdTimeout     int         `yaml:"pre_cmd_timeout"`
	PostCmdRun        string      `yaml:"post_cmd_run"`
	PostCmdTimeout    int         `yaml:"post_cmd_timeout"`
	RevokeOnUpdate    bool        `yaml:"revoke_on_update"`
	RevokeOnDelete    bool        `yaml:"revoke_on_delete"`
	DelayBeforeDelete string      `yaml:"delay_before_delete"`
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

	if s.Common.CertDirPerm == 0 {
		s.Common.CertDirPerm = 0700
	}

	if s.Common.CertFilePerm == 0 {
		s.Common.CertFilePerm = 0600
	}

	if s.Common.CertKeyFilePerm == 0 {
		s.Common.CertKeyFilePerm = 0600
	}

	if s.Common.CertTimeout == 0 {
		s.Common.CertTimeout = 180
	}

	if s.Common.CertFileExt == "" {
		s.Common.CertFileExt = ".crt"
	}

	if s.Common.CertKeyFileExt == "" {
		s.Common.CertKeyFileExt = ".key"
	}

	if s.Common.DelayBeforeDelete != "" {
		if _, err := model.ParseDuration(s.Common.DelayBeforeDelete); err != nil {
			return fmt.Errorf("invalid duration in 'delay_before_delete': %v", err)
		}
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
		if cert.KeyType != "" {
			_, err := utils.GetKeyType(cert.KeyType)
			if err != nil {
				return err
			}
		}

		if cert.Labels != "" {
			err := utils.ValidateLabels(cert.Labels)
			if len(err) != 0 {
				return fmt.Errorf("%s", err)
			}
		}
	}

	// Create base certificate directory if it doesn't exist and certificate_deploy is enabled
	if s.Common.CertDeploy && s.Common.CertDir != "" {
		if err := utils.CreateNonExistingFolder(s.Common.CertDir, s.Common.CertDirPerm); err != nil {
			return fmt.Errorf("failed to create certificate directory '%s': %v", s.Common.CertDir, err)
		}
	}

	return nil
}
