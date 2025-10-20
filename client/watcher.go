package client

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme-manager/metrics"
	"github.com/fgouteroux/acme-manager/restclient"
)

func WatchCertificateChange(logger log.Logger, interval time.Duration, configPath string, acmeClient *restclient.Client) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		// Compare and create/update certificate from config file to remote server
		CheckCertificate(logger, configPath, acmeClient)
	}
}

func WatchCertificateFromRing(logger log.Logger, interval time.Duration, configPath string, acmeClient *restclient.Client) {
	// create a new Ticker
	tk := time.NewTicker(interval)

	// start the ticker
	for range tk.C {
		// Compare and create/update certificate from config file to remote server
		PullAndCheckCertificateFromRing(logger, configPath, acmeClient)
	}
}

func WatchCertificateEventChange(logger log.Logger, configPath string, acmeClient *restclient.Client) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}
	defer watcher.Close()

	fileName := configPath
	watchDir := filepath.Dir(configPath)
	if watchDir == "." {
		fileName = "./" + configPath
	}

	// watch the parent dir of the file to catch changes
	err = watcher.Add(watchDir)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	for {
		select {
		case event := <-watcher.Events:
			// listen for CREATE/RENAME/WRITE events from original filename
			if (event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Rename == fsnotify.Rename) && event.Name == fileName {
				_ = level.Info(logger).Log("msg", fmt.Sprintf("modified file: %s", configPath))

				metrics.IncCertificateConfigReload()

				// Compare and create/update certificate from config file to remote server
				go CheckCertificate(logger, configPath, acmeClient)
			}
		case err := <-watcher.Errors:
			_ = level.Error(logger).Log("err", err)
		}
	}
}
