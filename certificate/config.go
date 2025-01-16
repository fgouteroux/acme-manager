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
	Domain         string `json:"domain" yaml:"domain" example:"testfgx.example.com"`
	Issuer         string `json:"issuer" yaml:"issuer" example:"letsencrypt"`
	Bundle         bool   `json:"bundle" yaml:"bundle" example:"false"`
	SAN            string `json:"san,omitempty" yaml:"san,omitempty" example:""`
	Days           int    `json:"days,omitempty" yaml:"days,omitempty" example:"90"`
	RenewalDays    int    `json:"renewal_days,omitempty" yaml:"renewal_days,omitempty" example:"30"`
	DNSChallenge   string `json:"dns_challenge,omitempty" yaml:"dns_challenge,omitempty" example:"ns1"`
	HTTPChallenge  string `json:"http_challenge,omitempty" yaml:"http_challenge,omitempty" example:""`
	Expires        string `json:"expires" example:"2025-04-09 09:56:34 +0000 UTC"`
	Fingerprint    string `json:"fingerprint" example:"3c7bccea1992d5095e7ab8c38f247352cd75ff26cdb95972d34ad54ebcef36af"`
	KeyFingerprint string `json:"key_fingerprint" example:"031312e2ea90eb8070c8da352c048171075f2ecfa3f300354bacc497e02247fc"`
	Owner          string `json:"owner" example:"testfgx"`
}

type CertMap struct {
	Certificate
	Cert     string `json:"cert" example:"LS0tLS1CRUdJTiBDR..."`
	Key      string `json:"key"  example:"LS0tLS1CRUdJTiBSU..."`
	CAIssuer string `json:"ca_issuer" example:"Ci0tLS0tQkVHSU4gQ0..."`
	URL      string `json:"url" example:"https://acme-staging-v02.api.letsencrypt.org/acme/cert/4b63b4e8b6109"`
}
