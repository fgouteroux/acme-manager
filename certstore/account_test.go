package certstore

import (
	"bytes"
	"encoding/json"
	"testing"
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
