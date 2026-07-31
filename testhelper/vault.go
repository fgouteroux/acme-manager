package testhelper

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/fgouteroux/acme-manager/config"
	vaultStorage "github.com/fgouteroux/acme-manager/storage/vault"

	vaultApi "github.com/hashicorp/vault/api"
)

const (
	defaultVaultAddr  = "http://127.0.0.1:8200"
	defaultVaultToken = "root"
)

// VaultTest wraps a client bound to a per-test AppRole and KV v2 mount on the
// Vault instance started by `make compose-up`.
type VaultTest struct {
	Client vaultStorage.Client

	root   *vaultApi.Client
	engine string
	role   string
	policy string
}

// Cleanup removes the mount, role and policy created for the test. Vault runs
// in dev mode and is discarded with the container, but every test shares the
// same instance, so each one tidies up after itself.
func (v VaultTest) Cleanup() {
	if v.root == nil {
		return
	}
	_ = v.root.Sys().Unmount(v.engine)
	_, _ = v.root.Logical().Delete("auth/approle/role/" + v.role)
	_ = v.root.Sys().DeletePolicy(v.policy)
}

// GetTestVaultServer returns a Vault client authenticated against a KV v2 mount
// created for this test alone.
//
// It talks to an external Vault dev server (VAULT_ADDR, default
// http://127.0.0.1:8200) instead of an in-process test cluster. Running Vault as
// a container alongside Pebble keeps github.com/hashicorp/vault and its
// transitive tree — Docker, database drivers, cloud SDKs — out of the module
// graph entirely.
//
// The debug argument is kept for backwards compatibility and ignored: server
// logs now belong to the container.
func GetTestVaultServer(t *testing.T, _ bool) VaultTest {
	t.Helper()

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = defaultVaultAddr
	}
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		token = defaultVaultToken
	}

	cfg := vaultApi.DefaultConfig()
	cfg.Address = addr
	client, err := vaultApi.NewClient(cfg)
	if err != nil {
		t.Fatalf("unable to create vault client for %s: %v", addr, err)
	}
	client.SetToken(token)

	if _, err := client.Sys().Health(); err != nil {
		t.Fatalf("vault is not reachable at %s (start it with `make compose-up`): %v", addr, err)
	}

	name := uniqueName(t)

	// The approle auth backend is shared by every test, so enabling it has to be
	// idempotent: a second attempt reports the path as already in use.
	err = client.Sys().EnableAuthWithOptions("approle", &vaultApi.EnableAuthOptions{Type: "approle"})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		t.Fatalf("unable to enable approle auth: %v", err)
	}

	err = client.Sys().Mount(name, &vaultApi.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	})
	if err != nil {
		t.Fatalf("unable to mount secret engine %s: %v", name, err)
	}

	v := VaultTest{root: client, engine: name, role: name, policy: name}

	err = client.Sys().PutPolicy(name, fmt.Sprintf(
		"path %q { capabilities = [\"create\", \"read\", \"list\", \"update\", \"delete\"] }", name+"/*"))
	if err != nil {
		v.Cleanup()
		t.Fatalf("unable to write policy %s: %v", name, err)
	}

	_, err = client.Logical().Write("auth/approle/role/"+name, map[string]interface{}{
		"token_policies": name,
	})
	if err != nil {
		v.Cleanup()
		t.Fatalf("unable to create approle role %s: %v", name, err)
	}

	res, err := client.Logical().Read("auth/approle/role/" + name + "/role-id")
	if err != nil {
		v.Cleanup()
		t.Fatalf("unable to read role-id: %v", err)
	}
	roleID, ok := res.Data["role_id"].(string)
	if !ok {
		v.Cleanup()
		t.Fatal("role_id missing from vault response")
	}

	res, err = client.Logical().Write("auth/approle/role/"+name+"/secret-id", nil)
	if err != nil {
		v.Cleanup()
		t.Fatalf("unable to generate secret-id: %v", err)
	}
	secretID, ok := res.Data["secret_id"].(string)
	if !ok {
		v.Cleanup()
		t.Fatal("secret_id missing from vault response")
	}

	v.Client = vaultStorage.Client{
		APIClient: client,
		Config: config.Vault{
			RoleID:       roleID,
			SecretID:     secretID,
			MountPath:    "approle",
			SecretEngine: name,
		},
	}
	return v
}

// uniqueName derives a Vault path from the test name plus random bytes, so
// tests sharing the instance never collide, including across reruns.
func uniqueName(t *testing.T) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("unable to generate a unique mount name: %v", err)
	}
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		default:
			return '-'
		}
	}, t.Name())
	return "unittest-" + safe + "-" + hex.EncodeToString(b)
}
