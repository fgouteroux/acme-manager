package certificate

import (
	"fmt"
	"slices"

	"github.com/fgouteroux/acme_manager/config"
)

// Config represents certificate config.
type Config struct {
	Certificate []Certificate `yaml:"certificate"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	var foundIssuers []string
	for _, cert := range s.Certificate {

		if cert.Days != 0 && cert.Issuer == "letsencrypt" {
			return fmt.Errorf("Unsupported parameter 'days' for certificate domain '%s' with '%s' issuer", cert.Domain, cert.Issuer)
		}

		if !slices.Contains(foundIssuers, cert.Issuer) {
			foundIssuers = append(foundIssuers, cert.Issuer)
		}
	}

	var unsupportedIssuers []string
	for _, issuer := range foundIssuers {
		if !slices.Contains(config.SupportedIssuers, issuer) {
			unsupportedIssuers = append(unsupportedIssuers, issuer)
		}
	}

	if len(unsupportedIssuers) > 0 {
		return fmt.Errorf("Unsupported issuers found: %v", unsupportedIssuers)
	}

	return nil
}

// Certificate represents issuer certificate.
type Certificate struct {
	Domain         string `json:"domain" yaml:"domain"`
	Issuer         string `json:"issuer" yaml:"issuer"`
	Bundle         bool   `json:"bundle" yaml:"bundle"`
	SAN            string `json:"san,omitempty" yaml:"san,omitempty"`
	Days           int    `json:"days,omitempty" yaml:"days,omitempty"`
	RenewalDays    int    `json:"renewal_days,omitempty" yaml:"renewal_days,omitempty"`
	DNSChallenge   string `json:"dns_challenge,omitempty" yaml:"dns_challenge,omitempty"`
	HTTPChallenge  string `json:"http_challenge,omitempty" yaml:"http_challenge,omitempty"`
	Expires        string `json:"expires"`
	Fingerprint    string `json:"fingerprint"`
	KeyFingerprint string `json:"key_fingerprint"`
}
