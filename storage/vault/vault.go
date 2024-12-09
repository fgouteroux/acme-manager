package vault

import (
	"context"
	"fmt"
	"strings"

	vaultApi "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"

	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
)

var (
	Client *VaultClient
)

type VaultClient struct {
    APIClient *vaultApi.Client
    config config.Vault
}

func InitVaultClient(cfg config.Vault) (*VaultClient, error) {
	client := &VaultClient{}
	config := vaultApi.DefaultConfig()
	config.Address = cfg.URL
	c, err := vaultApi.NewClient(config)
	if err != nil {
		return client, fmt.Errorf("unable to initialize Vault client: %w", err)
	}
	client.APIClient = c
	client.config = cfg

	return client, nil
}

func vaultAppRoleLogin(client *VaultClient) error {
	appRoleAuth, err := auth.NewAppRoleAuth(
		client.config.RoleID,
		&auth.SecretID{FromString: client.config.SecretID},
		auth.WithMountPath(client.config.MountPath),
	)
	if err != nil {
		return fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := client.APIClient.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return fmt.Errorf("no auth info was returned after login")
	}
	return nil
}

// List a key-value secret (kv-v2) after authenticating via AppRole.
func (client *VaultClient) ListSecretWithAppRole(secretPath string) ([]string, error) {

	err := vaultAppRoleLogin(client)
	if err != nil {
		return []string{}, err
	}
	path := client.config.SecretEngine + "/metadata/" + secretPath
	secrets, err := recursiveListSecret(client, path, "")
	if err != nil {
		return secrets, fmt.Errorf("unable to list secrets: %w", err)
	}
	return secrets, nil
}


// Fetches a key-value secret (kv-v2) after authenticating via AppRole.
func (client *VaultClient) GetSecretWithAppRole(secretPath string) (map[string]interface{}, error) {
	var data map[string]interface{}

	err := vaultAppRoleLogin(client)
	if err != nil {
		return data, err
	}

	secret, err := client.APIClient.KVv2(client.config.SecretEngine).Get(context.Background(), secretPath)
	if err != nil {
		metrics.IncGetFailedVaultSecret()
		return data, err
	}

	metrics.IncGetSuccessVaultSecret()

	return secret.Data, nil
}

// Put a key-value secret (kv-v2) after authenticating via AppRole.
func (client *VaultClient) PutSecretWithAppRole(secretPath string, data map[string]interface{}) error {
	err := vaultAppRoleLogin(client)
	if err != nil {
		return err
	}

	_, err = client.APIClient.KVv2(client.config.SecretEngine).Put(context.Background(), secretPath, data)
	if err != nil {
		metrics.IncPutFailedVaultSecret()
		return err
	}
	metrics.IncPutSuccessVaultSecret()

	return nil
}

// Delete a key-value secret (kv-v2) after authenticating via AppRole.
func (client *VaultClient) DeleteSecretWithAppRole(secretPath string) error {
	err := vaultAppRoleLogin(client)
	if err != nil {
		return err
	}

	err = client.APIClient.KVv2(client.config.SecretEngine).Delete(context.Background(), secretPath)
	if err != nil {
		metrics.IncDeleteFailedVaultSecret()
		return err
	}
	metrics.IncDeleteSuccessVaultSecret()

	return nil
}

// listSecret returns a list of secrets from Vault
func listSecret(client *VaultClient, path string) (*vaultApi.Secret, error) {
	secret, err := client.APIClient.Logical().List(path)
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
func recursiveListSecret(client *VaultClient, path, prefix string) ([]string, error) {
	secretList, err := listSecret(client, path)
	if err != nil {
		return []string{}, err
	}
	if secretList != nil {
		for _, secret := range secretList.Data["keys"].([]interface{}) {
			if strings.HasSuffix(secret.(string), "/") {
				_, err := recursiveListSecret(client, path+secret.(string), secret.(string))
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
