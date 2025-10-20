package certstore

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/sirupsen/logrus"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/http/memcached"
	"github.com/go-acme/lego/v4/providers/http/s3"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"

	"github.com/fgouteroux/acme-manager/config"
	"github.com/fgouteroux/acme-manager/metrics"
	"github.com/fgouteroux/acme-manager/utils"
)

var (
	AcmeClient = make(map[string]*lego.Client)
)

// Account represents a users local saved credentials.
type Account struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

/** Implementation of the registration.User interface **/

// GetEmail returns the email address for the account.
func (a *Account) GetEmail() string {
	return a.Email
}

// GetPrivateKey returns the private RSA account key.
func (a *Account) GetPrivateKey() crypto.PrivateKey {
	return a.key
}

// GetRegistration returns the server registration.
func (a *Account) GetRegistration() *registration.Resource {
	return a.Registration
}

func accountSave(account *Account, accountFilePath string) error {
	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return err
	}

	err = os.WriteFile(accountFilePath, jsonBytes, 0600)
	if err != nil {
		return fmt.Errorf("unable to save account file %s: %v", accountFilePath, err)
	}

	return nil
}

func tryRecoverRegistration(customLogger *logrus.Logger, cfg config.Config, privateKey crypto.PrivateKey, email, caDirURL, userAgent string) (*lego.Client, *registration.Resource, error) {
	// couldn't load account but got a key. Try to look the account up.
	conf := lego.NewConfig(&Account{key: privateKey, Email: email})
	conf.CADirURL = caDirURL
	conf.UserAgent = userAgent

	setRetryHTTPClient(conf, cfg, customLogger)
	client, err := lego.NewClient(conf)
	if err != nil {
		return client, nil, err
	}

	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		return client, nil, err
	}
	return client, reg, nil
}

func Setup(logger log.Logger, customLogger *logrus.Logger, cfg config.Config, version string) error {
	for issuer, issuerConf := range cfg.Issuer {
		accountFilePath := fmt.Sprintf("%s/%s/account.json", cfg.Common.RootPathAccount, issuer)
		accountBytes, err := os.ReadFile(filepath.Clean(accountFilePath))
		if err != nil {
			_ = level.Warn(logger).Log("err", err)
		}
		var account Account
		if len(accountBytes) > 0 {
			err = json.Unmarshal(accountBytes, &account)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
			}
		}
		privateKeyPath := fmt.Sprintf("%s/%s/private_key.pem", cfg.Common.RootPathAccount, issuer)

		if !utils.FileExists(privateKeyPath) {
			_ = level.Error(logger).Log("msg", fmt.Errorf("skipping issuer account '%s' because private key '%s' doesn't exists", issuer, privateKeyPath))
			metrics.SetIssuerConfigError(issuer, 1.0)
			continue
		}

		privateKeyBytes, err := os.ReadFile(filepath.Clean(privateKeyPath))
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			metrics.SetIssuerConfigError(issuer, 1.0)
			continue
		}
		account.key, err = certcrypto.ParsePEMPrivateKey(privateKeyBytes)
		if err != nil {
			_ = level.Error(logger).Log("msg", fmt.Errorf("unable parse private key '%s'", privateKeyPath), "err", err)
			metrics.SetIssuerConfigError(issuer, 1.0)
			continue
		}

		userAgent := fmt.Sprintf("acme-manager/%s", version)

		if account.Registration == nil || account.Registration.Body.Status == "" {
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Trying to recover registration account for private key '%s'", privateKeyPath))
			client, reg, err := tryRecoverRegistration(customLogger, cfg, account.key, issuerConf.Contact, issuerConf.CADirURL, userAgent)
			if err != nil {
				if strings.Contains(err.Error(), "urn:ietf:params:acme:error:accountDoesNotExist") {
					_ = level.Warn(logger).Log("err", err.Error())
				} else {
					metrics.SetIssuerConfigError(issuer, 1.0)
					_ = level.Error(logger).Log("msg", fmt.Sprintf("Unable to recover registration account for private key '%s'", privateKeyPath), "err", err)
					continue
				}
			}

			if reg == nil {
				if issuerConf.EAB {
					reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
						TermsOfServiceAgreed: true,
						Kid:                  issuerConf.KID,
						HmacEncoded:          issuerConf.HMAC,
					})
					if err != nil {
						_ = level.Error(logger).Log("err", err)
						continue
					}
				} else {
					reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
					if err != nil {
						_ = level.Error(logger).Log("err", err)
						continue
					}
				}
			} else {
				var contact string
				if len(reg.Body.Contact) > 0 {
					contact = strings.TrimPrefix(reg.Body.Contact[0], "mailto:")
				}
				if contact != issuerConf.Contact {
					conf := lego.NewConfig(&Account{key: account.key, Email: issuerConf.Contact, Registration: &registration.Resource{URI: reg.URI}})
					conf.CADirURL = issuerConf.CADirURL
					conf.UserAgent = userAgent

					setRetryHTTPClient(conf, cfg, customLogger)
					client, err := lego.NewClient(conf)
					if err != nil {
						continue
					}

					reg, err = client.Registration.UpdateRegistration(registration.RegisterOptions{TermsOfServiceAgreed: true})
					if err != nil {
						_ = level.Error(logger).Log("err", err)
						continue
					}
				}
			}
			var contact string
			if len(reg.Body.Contact) > 0 {
				contact = strings.TrimPrefix(reg.Body.Contact[0], "mailto:")
			}
			account.Email = contact
			account.Registration = reg
			err = accountSave(&account, accountFilePath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				return err
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Account file %s saved", accountFilePath))

		} else if account.Registration != nil && account.Email != issuerConf.Contact {

			conf := lego.NewConfig(&Account{key: account.key, Email: issuerConf.Contact, Registration: &registration.Resource{URI: account.Registration.URI}})
			conf.CADirURL = issuerConf.CADirURL
			conf.UserAgent = userAgent

			setRetryHTTPClient(conf, cfg, customLogger)
			client, err := lego.NewClient(conf)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}
			reg, err := client.Registration.UpdateRegistration(registration.RegisterOptions{TermsOfServiceAgreed: true})
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}
			var contact string
			if len(reg.Body.Contact) > 0 {
				contact = strings.TrimPrefix(reg.Body.Contact[0], "mailto:")
			}
			account.Email = contact
			account.Registration = reg
			err = accountSave(&account, accountFilePath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Account file %s updated", accountFilePath))
		} else if account.Registration != nil && issuerConf.Unregister {

			conf := lego.NewConfig(&Account{key: account.key, Email: issuerConf.Contact, Registration: &registration.Resource{URI: account.Registration.URI}})
			conf.CADirURL = issuerConf.CADirURL
			conf.UserAgent = userAgent

			setRetryHTTPClient(conf, cfg, customLogger)
			client, err := lego.NewClient(conf)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				continue
			}

			err = client.Registration.DeleteRegistration()
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Errorf("unable to unregister '%s' issuer account", issuer), "err", err)
				continue
			}
			_ = level.Info(logger).Log("msg", fmt.Sprintf("account deleted for private key '%s'", privateKeyPath))

			if utils.FileExists(accountFilePath) {
				err := os.Remove(accountFilePath)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to delete account file '%s'", accountFilePath), "err", err)
				}
			} else {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("account file '%s' deleted", accountFilePath))
			}

			if utils.FileExists(privateKeyPath) {
				err := os.Remove(privateKeyPath)
				if err != nil {
					_ = level.Error(logger).Log("msg", fmt.Sprintf("unable to delete private key '%s'", privateKeyPath), "err", err)
				}
			} else {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("account private key '%s' deleted", privateKeyPath))
			}
			delete(AcmeClient, issuer)
			continue
		}

		metrics.SetIssuerConfigError(issuer, 0.0)

		conf := lego.NewConfig(&account)
		conf.CADirURL = issuerConf.CADirURL
		conf.Certificate.KeyType = certcrypto.RSA2048
		conf.Certificate.OverallRequestLimit = issuerConf.OverallRequestLimit
		conf.Certificate.Timeout = time.Duration(issuerConf.CertificateTimeout) * time.Second
		conf.UserAgent = userAgent

		setRetryHTTPClient(conf, cfg, customLogger)
		client, err := lego.NewClient(conf)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			continue
		}

		AcmeClient[issuer] = client
	}
	return nil
}

// NewHTTPChallengeProviderByName Factory for HTTP providers.
func NewHTTPChallengeProviderByName(name, config string, logger log.Logger) (challenge.Provider, error) {
	switch name {
	case "memcached":
		return memcached.NewMemcachedProvider(strings.Split(config, ","))
	case "s3":
		return s3.NewHTTPProvider(config)
	case "webroot":
		return webroot.NewHTTPProvider(config)
	case "kvring":
		return NewKVRingProvider(logger)
	default:
		return nil, fmt.Errorf("unrecognized HTTP provider: %s", name)
	}
}

func setRetryHTTPClient(conf *lego.Config, cfg config.Config, customLogger *logrus.Logger) {
	retryClient := retryablehttp.NewClient()

	retryClient.RetryMax = 5
	if cfg.Common.HTTPClientRetryMax != 0 {
		retryClient.RetryMax = cfg.Common.HTTPClientRetryMax
	}
	retryClient.RetryWaitMin = 1 * time.Second
	if cfg.Common.HTTPClientRetryWaitMin != 0 {
		retryClient.RetryWaitMin = time.Duration(cfg.Common.HTTPClientRetryWaitMin) * time.Second
	}
	retryClient.RetryWaitMax = 10 * time.Second
	if cfg.Common.HTTPClientRetryWaitMax != 0 {
		retryClient.RetryWaitMax = time.Duration(cfg.Common.HTTPClientRetryWaitMax) * time.Second
	}

	retryClient.HTTPClient = conf.HTTPClient

	// Set the custom logger
	if customLogger != nil {
		retryClient.Logger = customLogger
		// Set the response log hook
		retryClient.ResponseLogHook = utils.ResponseLogHook(customLogger, false)
	} else {
		retryClient.Logger = nil
	}
	if len(cfg.Common.HTTPClientRetryStatusCode) > 0 {
		retryClient.CheckRetry = NewStatusCodeRetryPolicy(customLogger, cfg.Common.HTTPClientRetryStatusCode)
	}

	conf.HTTPClient = retryClient.StandardClient()
}

// NewStatusCodeRetryPolicy creates a CheckRetry function that retries
// on connection errors, 5xx status codes (default behavior), and
// any additional status codes provided in the `retryStatusCodes` list.
func NewStatusCodeRetryPolicy(customLogger *logrus.Logger, retryStatusCodes []int) retryablehttp.CheckRetry {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		// First, defer to the default retry policy for common errors (network, 5xx, etc.)
		shouldRetry, defaultErr := retryablehttp.DefaultRetryPolicy(ctx, resp, err)

		// If the default policy already decided to retry or an error occurred, return that.
		if shouldRetry || defaultErr != nil {
			return shouldRetry, defaultErr
		}

		// Now, check if the response status code is in our custom list.
		if resp != nil {
			for _, code := range retryStatusCodes {
				if resp.StatusCode == code {
					customLogger.Printf("Retrying on custom status code %d for URL: %s\n", code, resp.Request.URL)
					return true, nil
				}
			}
		}

		// Otherwise, do not retry.
		return false, nil
	}
}
