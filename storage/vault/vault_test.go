package vault_test

import (
	"testing"

	"github.com/fgouteroux/acme-manager/testhelper"
)

func TestVaultGetPutSecret(t *testing.T) {
	vaultTest := testhelper.GetTestVaultServer(t, false)
	defer vaultTest.Cluster.Cleanup()

	err := vaultTest.Client.PutSecretWithAppRole("test", map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = vaultTest.Client.GetSecretWithAppRole("test")
	if err != nil {
		t.Fatal(err)
	}

}

func TestVaultDeleteSecret(t *testing.T) {
	vaultTest := testhelper.GetTestVaultServer(t, false)
	defer vaultTest.Cluster.Cleanup()

	err := vaultTest.Client.PutSecretWithAppRole("test", map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}
	err = vaultTest.Client.DeleteSecretWithAppRole("test")
	if err != nil {
		t.Fatal(err)
	}

}

func TestVaultDestroySecret(t *testing.T) {
	vaultTest := testhelper.GetTestVaultServer(t, false)
	defer vaultTest.Cluster.Cleanup()

	err := vaultTest.Client.PutSecretWithAppRole("test", map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}
	err = vaultTest.Client.DestroySecretWithAppRole("test")
	if err != nil {
		t.Fatal(err)
	}

}

func TestVaultListSecret(t *testing.T) {
	vaultTest := testhelper.GetTestVaultServer(t, false)
	defer vaultTest.Cluster.Cleanup()

	err := vaultTest.Client.PutSecretWithAppRole("test/secret1", map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}

	err = vaultTest.Client.PutSecretWithAppRole("test/secret2", map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}
	list, err := vaultTest.Client.ListSecretWithAppRole("test")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Errorf("Expected list length to be 2, but got %d", len(list))
	}
}
