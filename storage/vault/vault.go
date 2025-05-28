package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	vaultApi "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/sirupsen/logrus"

	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/utils"
)

var (
	GlobalClient *Client
)

type Client struct {
	APIClient *vaultApi.Client
	Config    config.Vault
}

func InitClient(cfg config.Vault, logger *logrus.Logger) (*Client, error) {
	client := &Client{}
	config := vaultApi.DefaultConfig()
	config.Address = cfg.URL

	// Create a retryable HTTP client
	retryClient := retryablehttp.NewClient()

	retryClient.RetryMax = 3
	if cfg.RetryMax != 0 {
		retryClient.RetryMax = cfg.RetryMax
	}
	retryClient.RetryWaitMin = 1 * time.Second
	if cfg.RetryWaitMin != 0 {
		retryClient.RetryWaitMin = time.Duration(cfg.RetryWaitMin) * time.Second
	}
	retryClient.RetryWaitMax = 10 * time.Second
	if cfg.RetryWaitMax != 0 {
		retryClient.RetryWaitMax = time.Duration(cfg.RetryWaitMax) * time.Second
	}

	// Set the custom logger
	if logger != nil {
		retryClient.Logger = &utils.LogrusAdapter{Logger: logger}
		// Set the response log hook
		retryClient.ResponseLogHook = utils.ResponseLogHook()
	} else {
		retryClient.Logger = nil
	}

	// Set the HTTP client of the Vault client to the retryable HTTP client
	config.HttpClient = retryClient.StandardClient()

	c, err := vaultApi.NewClient(config)
	if err != nil {
		return client, fmt.Errorf("unable to initialize Vault client: %w", err)
	}
	client.APIClient = c
	client.Config = cfg

	return client, nil
}

func vaultAppRoleLogin(client *Client) error {
	appRoleAuth, err := auth.NewAppRoleAuth(
		client.Config.RoleID,
		&auth.SecretID{FromString: client.Config.SecretID},
		auth.WithMountPath(client.Config.MountPath),
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
func (client *Client) ListSecretWithAppRole(secretPath string) ([]string, error) {
	err := vaultAppRoleLogin(client)
	if err != nil {
		return []string{}, err
	}
	var secretListPath []string
	path := client.Config.SecretEngine + "/metadata/" + secretPath
	secrets, err := recursiveListSecret(client, path, secretListPath)
	if err != nil {
		return secrets, fmt.Errorf("unable to list secrets: %w", err)
	}
	return secrets, nil
}

// Fetches a key-value secret (kv-v2) after authenticating via AppRole.
func (client *Client) GetSecretWithAppRole(secretPath string) (map[string]interface{}, error) {
	var data map[string]interface{}

	err := vaultAppRoleLogin(client)
	if err != nil {
		return data, err
	}

	secret, err := client.APIClient.KVv2(client.Config.SecretEngine).Get(context.Background(), secretPath)
	if err != nil {
		metrics.IncGetFailedVaultSecret()
		return data, err
	}

	metrics.IncGetSuccessVaultSecret()

	return secret.Data, nil
}

// Put a key-value secret (kv-v2) after authenticating via AppRole.
func (client *Client) PutSecretWithAppRole(secretPath string, data map[string]interface{}) error {
	err := vaultAppRoleLogin(client)
	if err != nil {
		return err
	}

	_, err = client.APIClient.KVv2(client.Config.SecretEngine).Put(context.Background(), secretPath, data)
	if err != nil {
		metrics.IncPutFailedVaultSecret()
		return err
	}
	metrics.IncPutSuccessVaultSecret()

	return nil
}

// Delete a key-value secret (kv-v2) after authenticating via AppRole.
func (client *Client) DeleteSecretWithAppRole(secretPath string) error {
	err := vaultAppRoleLogin(client)
	if err != nil {
		return err
	}

	err = client.APIClient.KVv2(client.Config.SecretEngine).Delete(context.Background(), secretPath)
	if err != nil {
		metrics.IncDeleteFailedVaultSecret()
		return err
	}
	metrics.IncDeleteSuccessVaultSecret()

	return nil
}

// Delete permanently a key-value secret (kv-v2) after authenticating via AppRole.
func (client *Client) DestroySecretWithAppRole(secretPath string) error {
	err := vaultAppRoleLogin(client)
	if err != nil {
		return err
	}

	metaVersions, err := client.APIClient.KVv2(client.Config.SecretEngine).GetVersionsAsList(context.Background(), secretPath)
	if err != nil {
		metrics.IncDeleteFailedVaultSecret()
		return err
	}

	var versionList []int
	for _, meta := range metaVersions {
		versionList = append(versionList, meta.Version)
	}

	err = client.APIClient.KVv2(client.Config.SecretEngine).Destroy(context.Background(), secretPath, versionList)
	if err != nil {
		metrics.IncDeleteFailedVaultSecret()
		return err
	}

	err = client.APIClient.KVv2(client.Config.SecretEngine).DeleteMetadata(context.Background(), secretPath)
	if err != nil {
		metrics.IncDeleteFailedVaultSecret()
		return err
	}

	metrics.IncDeleteSuccessVaultSecret()

	return nil
}

// listSecret returns a list of secrets from Vault
func listSecret(client *Client, path string) (*vaultApi.Secret, error) {
	secret, err := client.APIClient.Logical().List(path)
	if err != nil {
		return secret, err
	}

	/*
		if secret == nil {
			return secret, fmt.Errorf("couldn't list %s from the Vault", path)
		}
	*/
	return secret, err
}

// recursiveListSecret returns a list of secrets paths from Vault
func recursiveListSecret(client *Client, path string, secretListPath []string) ([]string, error) {
	secretList, err := listSecret(client, path)
	if err != nil {
		return []string{}, err
	}

	if secretList != nil {
		for _, secret := range secretList.Data["keys"].([]interface{}) {
			if strings.HasSuffix(secret.(string), "/") {
				var err error
				secretListPath, err = recursiveListSecret(client, path+secret.(string), secretListPath)
				if err != nil {
					return []string{}, err
				}
			} else {
				// remove secret engine + metadata path as it is implicit in GetSecretWithAppRole
				secretPath := strings.Split(path, client.Config.SecretEngine+"/metadata")[1] + secret.(string)
				secretListPath = append(secretListPath, secretPath)
			}
		}
	}
	return secretListPath, nil
}
