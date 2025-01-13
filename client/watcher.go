package client

import (
	"time"

	"github.com/go-kit/log"

	"github.com/fgouteroux/acme_manager/restclient"
)

func WatchCertificate(logger log.Logger, interval time.Duration, configPath string, acmeClient *restclient.Client) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {

		// Compare and create/update certificate from config file to remote server
		CheckCertificate(logger, configPath, acmeClient)

		// check local certificate are up-to-date
		CheckAndDeployLocalCertificate(logger, acmeClient)
	}
}
