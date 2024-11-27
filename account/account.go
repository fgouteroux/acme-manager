package account

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"encoding/json"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/ns1"
	"github.com/go-acme/lego/v4/registration"

	"github.com/fgouteroux/acme_manager/config"
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
		return fmt.Errorf("Unable to save account file %s: %v", accountFilePath, err)
	}

	return nil
}

func tryRecoverRegistration(privateKey crypto.PrivateKey, caDirURL, userAgent string) (*lego.Client, *registration.Resource, error) {
	// couldn't load account but got a key. Try to look the account up.
	conf := lego.NewConfig(&Account{key: privateKey})
	conf.CADirURL = caDirURL
	conf.UserAgent = userAgent

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

func Setup(logger log.Logger, cfg config.Config) error {
	for issuer, issuerConf := range cfg.Issuer {
		accountFilePath := fmt.Sprintf("%s/%s/account.json", cfg.Common.RootPathAccount, issuer)
		accountBytes, err := os.ReadFile(filepath.Clean(accountFilePath))
		if err != nil {
			level.Warn(logger).Log("err", err) // #nosec G104
		}
		var account Account
		err = json.Unmarshal(accountBytes, &account)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return err
		}

		privateKeyBytes, err := os.ReadFile(fmt.Sprintf("%s/%s/private_key.pem", cfg.Common.RootPathAccount, issuer))
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return err
		}
		privateKey, err := certcrypto.ParsePEMPrivateKey(privateKeyBytes)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return err
		}
		account.key = privateKey

		userAgent := fmt.Sprintf("acme-manager/%s", "1.0")

		if account.Registration == nil || account.Registration.Body.Status == "" {
			client, reg, err := tryRecoverRegistration(privateKey, issuerConf.CADirURL, userAgent)
			if err != nil {

				if issuerConf.EAB {
					reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
						TermsOfServiceAgreed: true,
						Kid:                  issuerConf.KID,
						HmacEncoded:          issuerConf.HMAC,
					})
					if err != nil {
						level.Error(logger).Log("err", err) // #nosec G104
						return err
					}
				} else {
					reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
					if err != nil {
						level.Error(logger).Log("err", err) // #nosec G104
						return err
					}
				}
			}
			account.Email = strings.TrimPrefix(reg.Body.Contact[0], "mailto:")
			account.Registration = reg
			err = accountSave(&account, accountFilePath)
			if err != nil {
				level.Error(logger).Log("err", err) // #nosec G104
				return err
			}
		}

		conf := lego.NewConfig(&account)
		conf.CADirURL = issuerConf.CADirURL
		conf.Certificate.KeyType = certcrypto.RSA2048
		conf.UserAgent = userAgent

		client, err := lego.NewClient(conf)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return err
		}

		// env var NS1_API_KEY must exist
		dnsProvider, err := ns1.NewDNSProvider()
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return err
		}

		err = client.Challenge.SetDNS01Provider(dnsProvider)
		if err != nil {
			level.Error(logger).Log("err", err) // #nosec G104
			return err
		}
		AcmeClient[issuer] = client
	}
	return nil
}
