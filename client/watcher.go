package client

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme-manager/metrics"
	"github.com/fgouteroux/acme-manager/restclient"
)

const debounceDelay = 500 * time.Millisecond

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
		_ = level.Error(logger).Log("msg", "failed to create file watcher", "err", err)
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
		_ = level.Error(logger).Log("msg", "failed to watch directory", "path", watchDir, "err", err)
		os.Exit(1)
	}

	// Debounce mechanism to coalesce rapid file events into a single check
	var debounceTimer *time.Timer
	var debounceMu sync.Mutex

	for {
		select {
		case event := <-watcher.Events:
			// listen for CREATE/RENAME/WRITE events from original filename
			if (event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Rename == fsnotify.Rename) && event.Name == fileName {
				_ = level.Debug(logger).Log("msg", fmt.Sprintf("file event detected: %s (op: %s)", configPath, event.Op))

				debounceMu.Lock()
				// Reset the timer on each event to wait for events to settle
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(debounceDelay, func() {
					_ = level.Info(logger).Log("msg", fmt.Sprintf("modified file: %s", configPath))
					metrics.IncCertificateConfigReload()
					// Compare and create/update certificate from config file to remote server
					CheckCertificate(logger, configPath, acmeClient)
				})
				debounceMu.Unlock()
			}
		case err := <-watcher.Errors:
			_ = level.Error(logger).Log("msg", "file watcher error", "err", err)
		}
	}
}
