package vault

import (
	"context"
	"fmt"
	"strings"

	vaultApi "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"

	"github.com/fgouteroux/acme_manager/config"
)

var (
	VaultClient *vaultApi.Client
)

func InitVaultClient(cfg config.Vault) (*vaultApi.Client, error) {
	config := vaultApi.DefaultConfig()
	config.Address = cfg.URL

	client, err := vaultApi.NewClient(config)
	if err != nil {
		return client, fmt.Errorf("unable to initialize Vault client: %w", err)
	}
	return client, nil
}

func vaultAppRoleLogin(client *vaultApi.Client, cfg config.Vault) error {
	appRoleAuth, err := auth.NewAppRoleAuth(
		cfg.RoleID,
		&auth.SecretID{FromString: cfg.SecretID},
		auth.WithMountPath(cfg.MountPath),
	)
	if err != nil {
		return fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return fmt.Errorf("no auth info was returned after login")
	}
	return nil
}

// Fetches a key-value secret (kv-v2) after authenticating via AppRole.
func GetSecretWithAppRole(client *vaultApi.Client, cfg config.Vault, secretPath string) (map[string]interface{}, error) {
	var data map[string]interface{}

	err := vaultAppRoleLogin(client, cfg)
	if err != nil {
		return data, err
	}

	secret, err := client.KVv2(cfg.SecretEngine).Get(context.Background(), secretPath)
	if err != nil {
		return data, err
	}

	return secret.Data, nil
}

// Put a key-value secret (kv-v2) after authenticating via AppRole.
func PutSecretWithAppRole(client *vaultApi.Client, cfg config.Vault, secretPath string, data map[string]interface{}) error {
	err := vaultAppRoleLogin(client, cfg)
	if err != nil {
		return err
	}

	_, err = client.KVv2(cfg.SecretEngine).Put(context.Background(), secretPath, data)
	if err != nil {
		return err
	}

	return nil
}

// Delete a key-value secret (kv-v2) after authenticating via AppRole.
func DeleteSecretWithAppRole(client *vaultApi.Client, cfg config.Vault, secretPath string) error {
	err := vaultAppRoleLogin(client, cfg)
	if err != nil {
		return err
	}

	err = client.KVv2(cfg.SecretEngine).Delete(context.Background(), secretPath)
	if err != nil {
		return err
	}

	return nil
}

// listSecret returns a list of secrets from Vault
func listSecret(vaultCli *vaultApi.Client, path string) (*vaultApi.Secret, error) {
	secret, err := vaultCli.Logical().List(path)
	if err != nil {
		return secret, err
	}

	if secret == nil {
		return secret, fmt.Errorf("couldn't list %s from the Vault", path)
	}
	return secret, err
}

var secretListPath []string

// recursiveListSecret returns a list of secrets paths from Vault
func recursiveListSecret(vaultCli *vaultApi.Client, path, prefix string) ([]string, error) {
	secretList, err := listSecret(vaultCli, path)
	if err != nil {
		return []string{}, err
	}
	if secretList != nil {
		for _, secret := range secretList.Data["keys"].([]interface{}) {
			if strings.HasSuffix(secret.(string), "/") {
				_, err := recursiveListSecret(vaultCli, path+secret.(string), secret.(string))
				if err != nil {
					return []string{}, err
				}
			} else if prefix != "" {
				secretListPath = append([]string{prefix + secret.(string)}, secretListPath...)
			} else {
				secretListPath = append([]string{secret.(string)}, secretListPath...)
			}
		}
	}
	return secretListPath, nil
}

// List a key-value secret (kv-v2) after authenticating via AppRole.
func ListSecretWithAppRole(client *vaultApi.Client, cfg config.Vault, secretPath string) ([]string, error) {

	err := vaultAppRoleLogin(client, cfg)
	if err != nil {
		return []string{}, err
	}
	path := cfg.SecretEngine + "/metadata/" + secretPath
	secrets, err := recursiveListSecret(client, path, "")
	if err != nil {
		return secrets, fmt.Errorf("unable to list secrets: %w", err)
	}
	return secrets, nil
}
