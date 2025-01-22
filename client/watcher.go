package client

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/restclient"
)

func WatchLocalCertificate(logger log.Logger, interval time.Duration, acmeClient *restclient.Client) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		// check local certificate are up-to-date
		CheckAndDeployLocalCertificate(logger, acmeClient)
	}
}

func WatchCertificateUpdate(logger log.Logger, configPath string, acmeClient *restclient.Client) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}
	defer watcher.Close()

	fileName := filepath.Base(configPath)
	if !filepath.IsAbs(configPath) {
		fileName = "./" + fileName
	}

	// watch the parent dir of the file to catch changes
	err = watcher.Add(filepath.Dir(configPath))
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	for {
		select {
		case event := <-watcher.Events:
			// only work on WRITE events of the original filename
			if event.Op&fsnotify.Write == fsnotify.Write && event.Name == fileName {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("modified file: %s", configPath))

				metrics.IncCertificateConfigReload()

				// Compare and create/update certificate from config file to remote server
				CheckCertificate(logger, configPath, acmeClient)

				// check local certificate are up-to-date
				CheckAndDeployLocalCertificate(logger, acmeClient)
			}
		case err := <-watcher.Errors:
			_ = level.Error(logger).Log("err", err)
		}
	}
}
