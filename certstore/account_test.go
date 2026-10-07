package certstore

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/go-acme/lego/v5/acme"
)

const testAccountURL = "https://acme.example.com/acct/42"

func TestAccountUnmarshalJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{
			name: "current layout",
			data: `{"email":"ssl@example.com","registration":{"status":"valid","contact":["mailto:ssl@example.com"],"accountURL":"` + testAccountURL + `"}}`,
		},
		{
			name: "legacy layout written before lego v5.5.2",
			data: `{"email":"ssl@example.com","registration":{"body":{"status":"valid","contact":["mailto:ssl@example.com"]},"uri":"` + testAccountURL + `"}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var account Account
			if err := json.Unmarshal([]byte(tc.data), &account); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if account.Email != "ssl@example.com" {
				t.Errorf("Email = %q, want ssl@example.com", account.Email)
			}
			if account.Registration == nil {
				t.Fatal("Registration is nil")
			}
			if account.Registration.Status != "valid" {
				t.Errorf("Status = %q, want valid", account.Registration.Status)
			}
			if account.Registration.Location != testAccountURL {
				t.Errorf("Location = %q, want %q", account.Registration.Location, testAccountURL)
			}
			if got := account.Registration.Contact; len(got) != 1 || got[0] != "mailto:ssl@example.com" {
				t.Errorf("Contact = %v, want [mailto:ssl@example.com]", got)
			}
		})
	}
}

// A file read in the legacy layout is written back in the current one, so the
// conversion happens on the next save instead of needing a migration step.
func TestAccountMarshalUsesCurrentLayout(t *testing.T) {
	legacy := `{"email":"ssl@example.com","registration":{"body":{"status":"valid"},"uri":"` + testAccountURL + `"}}`

	var account Account
	if err := json.Unmarshal([]byte(legacy), &account); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	out, err := json.Marshal(&account)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, legacyKey := range []string{`"body"`, `"uri"`} {
		if bytes.Contains(out, []byte(legacyKey)) {
			t.Errorf("output still carries the legacy key %s: %s", legacyKey, out)
		}
	}
	if !bytes.Contains(out, []byte(`"accountURL":"`+testAccountURL+`"`)) {
		t.Errorf("account URL missing from output: %s", out)
	}
}

// An account file with no registration at all must stay nil so that Setup()
// still routes the issuer through registration.
func TestAccountUnmarshalJSONWithoutRegistration(t *testing.T) {
	var account Account
	if err := json.Unmarshal([]byte(`{"email":"ssl@example.com"}`), &account); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if account.Registration != nil {
		t.Errorf("Registration = %+v, want nil", account.Registration)
	}
}

func TestAccountEmail(t *testing.T) {
	const configured = "ssl@example.com"

	for _, tc := range []struct {
		name string
		reg  *acme.ExtendedAccount
		want string
	}{
		{
			name: "CA echoes the contact back",
			reg:  &acme.ExtendedAccount{Account: acme.Account{Contact: []string{"mailto:ops@example.com"}}},
			want: "ops@example.com",
		},
		{
			// Let's Encrypt answers without a contact; the configured one must win
			// instead of being overwritten with an empty string.
			name: "CA echoes no contact",
			reg:  &acme.ExtendedAccount{},
			want: configured,
		},
		{
			name: "no registration at all",
			reg:  nil,
			want: configured,
		},
		{
			name: "contact without the mailto scheme",
			reg:  &acme.ExtendedAccount{Account: acme.Account{Contact: []string{"ops@example.com"}}},
			want: "ops@example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := accountEmail(tc.reg, configured); got != tc.want {
				t.Errorf("accountEmail() = %q, want %q", got, tc.want)
			}
		})
	}
}
