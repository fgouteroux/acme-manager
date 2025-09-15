package models

type CertMap struct {
	*Certificate
	Cert     string `json:"cert" example:"-----BEGIN CERTIFICATE-----\n..."`
	CAIssuer string `json:"ca_issuer" example:"-----BEGIN CERTIFICATE-----\n..."`
	URL      string `json:"url" example:"https://acme-staging-v02.api.letsencrypt.org/acme/cert/4b63b4e8b6109"`
}

type CertificateParams struct {
	Domain        string `json:"domain" example:"testfgx.example.com"`
	Issuer        string `json:"issuer" example:"letsencrypt"`
	Bundle        bool   `json:"bundle" example:"false"`
	San           string `json:"san,omitempty" example:""`
	Csr           string `json:"csr,omitempty"`
	Days          int    `json:"days,omitempty" example:"90"`
	RenewalDays   string `json:"renewal_days,omitempty" example:"30"`
	DNSChallenge  string `json:"dns_challenge,omitempty" example:"ns1"`
	HTTPChallenge string `json:"http_challenge,omitempty" example:""`
	Revoke        bool   `json:"revoke"`
	Labels        string `json:"labels"`
	KeyType       string `json:"key_type"`
}
