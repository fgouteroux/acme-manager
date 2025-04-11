package config

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    Config
		wantErr bool
	}{
		{
			name: "valid config",
			yaml: `
common:
  api_key_hash: "hash123"
  cert_days_renewal: "25-35"
  rootpath_account: "/account"
  rootpath_certificate: "/cert"
issuer:
  issuer1:
    contact: "admin@example.com"
    ca_dir_url: "https://ca.example.com"
    dns_challenge: "dns-provider"
    overall_request_limit: 20
    certificate_timeout: 40
  issuer2:
    contact: "admin@example.com"
    ca_dir_url: "https://ca.example.com"
    http_challenge: "http-provider"
    http_challenge_config: "config"
    overall_request_limit: 18
    certificate_timeout: 30
storage:
  vault:
    role_id: "role123"
    secret_id: "secret123"
    url: "https://vault.example.com"
    secret_engine: "engine"
    certificate_prefix: "cert_"
    token_prefix: "token_"
    mount_path: "/mount"
`,
			want: Config{
				Common: Common{
					APIKeyHash:          "hash123",
					CertDaysRenewal:     "25-35",
					RootPathAccount:     "/account",
					RootPathCertificate: "/cert",
				},
				Issuer: map[string]Issuer{
					"issuer1": {
						Contact:             "admin@example.com",
						CADirURL:            "https://ca.example.com",
						DNSChallenge:        "dns-provider",
						OverallRequestLimit: 20,
						CertificateTimeout:  40,
					},
					"issuer2": {
						Contact:             "admin@example.com",
						CADirURL:            "https://ca.example.com",
						HTTPChallenge:       "http-provider",
						HTTPChallengeCfg:    "config",
						OverallRequestLimit: 18,
						CertificateTimeout:  30,
					},
				},
				Storage: Storage{
					Vault: Vault{
						RoleID:       "role123",
						SecretID:     "secret123",
						URL:          "https://vault.example.com",
						SecretEngine: "engine",
						CertPrefix:   "cert_",
						TokenPrefix:  "token_",
						MountPath:    "/mount",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing challenge config",
			yaml: `
common:
  api_key_hash: "hash123"
issuer:
  issuer1:
    contact: "admin@example.com"
    ca_dir_url: "https://ca.example.com"
storage:
  vault:
    role_id: "role123"
`,
			wantErr: true,
		},
		{
			name: "mutually exclusive challenges",
			yaml: `
common:
  api_key_hash: "hash123"
issuer:
  issuer1:
    contact: "admin@example.com"
    ca_dir_url: "https://ca.example.com"
    dns_challenge: "dns-provider"
    http_challenge: "http-provider"
storage:
  vault:
    role_id: "role123"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := yaml.Unmarshal([]byte(tt.yaml), &cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalYAML() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(cfg, tt.want) {
				t.Errorf("UnmarshalYAML() got = %v, want %v", cfg, tt.want)
			}
		})
	}
}
