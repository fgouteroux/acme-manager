package client

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-kit/log"

	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/utils"
)

func TestCheckServerFingerprint(t *testing.T) {
	const cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

	testCases := []struct {
		name        string
		fingerprint string
		wantWarn    bool
	}{
		{
			name:        "content matches the advertised fingerprint",
			fingerprint: utils.GenerateFingerprint([]byte(cert)),
			wantWarn:    false,
		},
		{
			name:        "metadata holds the fingerprint of an older certificate",
			fingerprint: utils.GenerateFingerprint([]byte("older certificate")),
			wantWarn:    true,
		},
		{
			name:        "metadata carries no fingerprint at all",
			fingerprint: "",
			wantWarn:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := log.NewLogfmtLogger(&buf)

			meta := models.Certificate{
				Issuer:      "sectigo",
				Domain:      "example.com",
				Fingerprint: tc.fingerprint,
			}
			checkServerFingerprint(logger, meta, cert)

			gotWarn := strings.Contains(buf.String(), "does not match the fingerprint in its metadata")
			if gotWarn != tc.wantWarn {
				t.Errorf("warning logged = %v, want %v (log: %q)", gotWarn, tc.wantWarn, buf.String())
			}
		})
	}
}
