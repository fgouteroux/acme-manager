package testhelper

import (
	"testing"

	"github.com/hashicorp/go-hclog"

	"github.com/fgouteroux/acme-manager/config"
	vaultStorage "github.com/fgouteroux/acme-manager/storage/vault"

	vaultApi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/approle"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

const (
	// TestVaultToken is the Vault token used for tests
	testVaultToken = "unittesttoken"
)

type VaultTest struct {
	Cluster *vault.TestCluster
	Client  vaultStorage.Client
}

type Client struct {
	APIClient *vaultApi.Client
	Config    config.Vault
}

// creates the test server
func GetTestVaultServer(t *testing.T, debug bool) VaultTest {
	t.Helper()

	logger := hclog.NewNullLogger()
	if debug {
		logger = hclog.New(&hclog.LoggerOptions{
			Level: hclog.Debug,
		})
	}

	cluster := vault.NewTestCluster(t, &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		DevToken:     testVaultToken,
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
		Logger: logger,
	}, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	err := client.Sys().EnableAuthWithOptions("approle", &vaultApi.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create an approle
	_, err = client.Logical().Write("auth/approle/role/unittest", map[string]interface{}{
		"policies": []string{"unittest"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Gets the role ID, that is basically the 'username' used to log into vault
	res, err := client.Logical().Read("auth/approle/role/unittest/role-id")
	if err != nil {
		t.Fatal(err)
	}

	// Keep the roleID for later use
	roleID, ok := res.Data["role_id"].(string)
	if !ok {
		t.Fatal("Could not read the approle")
	}

	// Create a secretID that is basically the password for the approle
	res, err = client.Logical().Write("auth/approle/role/unittest/secret-id", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Use thre secretID later
	secretID, ok := res.Data["secret_id"].(string)
	if !ok {
		t.Fatal("Could not generate the secret id")
	}

	// Create a broad policy to allow the approle to do whatever
	err = client.Sys().PutPolicy("unittest", `
        path "*" {
            capabilities = ["create", "read", "list", "update", "delete"]
        }
    `)
	if err != nil {
		t.Fatal(err)
	}

	// Enable the KV secret engine
	mountPath := "unittest"
	err = client.Sys().Mount(mountPath, &vaultApi.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2", // Use version 2 of the KV secret engine
		},
	})
	if err != nil {
		t.Fatalf("Unable to mount secret engine: %v", err)
	}

	return VaultTest{
		Cluster: cluster,
		Client: vaultStorage.Client{
			APIClient: client,
			Config: config.Vault{
				RoleID:       roleID,
				SecretID:     secretID,
				MountPath:    "approle",
				SecretEngine: "unittest",
			},
		},
	}
}
