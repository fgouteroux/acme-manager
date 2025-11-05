package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/sirupsen/logrus"

	legoLog "github.com/go-acme/lego/v4/log"

	"github.com/fgouteroux/acme-manager/client"
	"github.com/fgouteroux/acme-manager/restclient"
	"github.com/fgouteroux/acme-manager/storage/vault"
	"github.com/fgouteroux/acme-manager/utils"

	"gopkg.in/yaml.v3"
)

var (
	// Logging flags
	logLevel  = flag.String("log.level", "info", "Only log messages with the given severity or above. One of: [debug, info, warn, error].")
	logFormat = flag.String("log.format", "logfmt", "Output format of log messages. One of: [logfmt, json].")

	// Server flags (minimal for client)
	serverListenAddress     = flag.String("server.listen-address", ":8989", "Server listen address.")
	serverTLSCertFile       = flag.String("server.tls-cert-file", "", "Server tls certificate file.")
	serverTLSKeyFile        = flag.String("server.tls-key-file", "", "Server tls key file.")
	serverReadTimeout       = flag.Int("server.http-read-timeout", 300, "Read timeout for entire HTTP request, including headers and body.")
	serverReadHeaderTimeout = flag.Int("server.http-read-header-timeout", 10, "Read timeout for HTTP request headers.")

	// Client flags
	clientPullOnly             = flag.Bool("client.pull-only", false, "Set client in pull mode. Manage local certificate files based on remote server changes.")
	clientManagerURL           = flag.String("client.manager-url", "http://localhost:8989/api/v1", "Client manager URL (can be set via ACME_MANAGER_URL env var).")
	clientManagerToken         = flag.String("client.manager-token", "", "Client manager token (can be set via ACME_MANAGER_TOKEN env var).")
	clientManagerTLSCAFile     = flag.String("client.tls-ca-file", "", "Client manager tls ca certificate file.")
	clientManagerTLSCertFile   = flag.String("client.tls-cert-file", "", "Client manager tls certificate file.")
	clientManagerTLSKeyFile    = flag.String("client.tls-key-file", "", "Client manager tls key file.")
	clientManagerTLSSkipVerify = flag.Bool("client.tls-skip-verify", false, "Client manager tls skip verify.")
	clientConfigPath           = flag.String("client.config-path", "client-config.yml", "Client config path.")
	clientCheckConfigInterval  = flag.Duration("client.check-config-interval", 5*time.Minute, "Time interval to check if client config file changes and to update local certificate file.")
	clientCleanupEnabled       = flag.Bool("client.cleanup-enabled", false, "Enable cleanup of local certificate files not found on acme manager server.")
	clientCleanupInterval      = flag.Duration("client.cleanup-interval", 30*time.Minute, "Time interval to cleanup certificate files not found on acme manager server.")

	// Help flags
	showVersion = flag.Bool("version", false, "Show version information")

	logger log.Logger
)

func main() {
	// Simple usage function for client
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "\nACME Manager Client - Manages local certificates from cluster\n")
		fmt.Fprintf(os.Stdout, "Version: %s\n\n", version.Info())
		fmt.Fprintf(os.Stdout, "Flags:\n")
		flag.PrintDefaults()
	}

	// Check for help flags BEFORE parsing
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "-help" || arg == "--help" {
			flag.Usage()
			os.Exit(0)
		}
	}

	// Parse flags
	flag.Parse()

	// Handle environment variables for client manager settings
	if envURL := os.Getenv("ACME_MANAGER_URL"); envURL != "" && *clientManagerURL == "http://localhost:8989/api/v1" {
		*clientManagerURL = envURL
	}
	if envToken := os.Getenv("ACME_MANAGER_TOKEN"); envToken != "" && *clientManagerToken == "" {
		*clientManagerToken = envToken
	}

	// Handle version flag
	if *showVersion {
		fmt.Println(version.Print("acme-manager-client"))
		os.Exit(0)
	}

	// set custom logger
	logrusLogger := logrus.New()
	logrusLogger.SetReportCaller(true)

	parsedLogLevel, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		parsedLogLevel = logrus.InfoLevel
	}
	logrusLogger.SetLevel(parsedLogLevel)

	if *logFormat == "json" {
		logrusLogger.SetFormatter(utils.UTCFormatter{Formatter: &logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime: "ts",
				logrus.FieldKeyFile: "caller",
			},
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				return "", fmt.Sprintf("%s:%d", utils.FormatFilePath(f.File), f.Line)
			},
		}})
	} else {
		logrusLogger.SetFormatter(&utils.CustomTextFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
		})
	}

	logrusLogger.SetOutput(&utils.CustomWriter{Writer: os.Stdout})
	logrusLogger.AddHook(&utils.DebugLevelHook{Logger: logrusLogger})

	// Override lego logger
	legoLog.Logger = logrusLogger

	// Create go-kit logger
	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	if *logFormat == "json" {
		logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	}
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.Caller(5))

	// Set log level for go-kit logger
	switch *logLevel {
	case "debug":
		logger = level.NewFilter(logger, level.AllowDebug())
	case "info":
		logger = level.NewFilter(logger, level.AllowInfo())
	case "warn":
		logger = level.NewFilter(logger, level.AllowWarn())
	case "error":
		logger = level.NewFilter(logger, level.AllowError())
	default:
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	configBytes, err := os.ReadFile(*clientConfigPath)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	var cfg client.Config
	err = yaml.Unmarshal(configBytes, &cfg)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	client.GlobalConfig = cfg

	if cfg.Common.CertBackup || *clientPullOnly {
		vault.GlobalClient, err = vault.InitClient(cfg.Storage.Vault, logrusLogger)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			os.Exit(1)
		}
	}

	if *clientManagerToken == "" {
		_ = level.Error(logger).Log("err", "Missing client manager token, please set '--client.manager-token' or env var 'ACME_MANAGER_TOKEN'")
		os.Exit(1)
	}

	acmeClient, err := restclient.NewClient(
		*clientManagerURL,
		*clientManagerToken,
		*clientManagerTLSCertFile,
		*clientManagerTLSKeyFile,
		*clientManagerTLSCAFile,
		*clientManagerTLSSkipVerify,
		logrusLogger,
	)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	token, err := acmeClient.GetSelfToken(30)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}
	client.Owner = token.Username

	_ = prometheus.Register(client.NewCertificateCollector())

	if *clientPullOnly {
		// On startup get certificates from remote server
		client.PullAndCheckCertificateFromRing(logger, *clientConfigPath, acmeClient)

		// periodically check local certificate are up-to-date
		go client.WatchCertificateFromRing(logger, *clientCheckConfigInterval, *clientConfigPath, acmeClient)
	} else {
		// On startup compare and create/update certificate from config file to remote server
		client.CheckCertificate(logger, *clientConfigPath, acmeClient)

		// periodically check local certificate are up-to-date
		go client.WatchCertificateChange(logger, *clientCheckConfigInterval, *clientConfigPath, acmeClient)

		// listen for config file event change
		go client.WatchCertificateEventChange(logger, *clientConfigPath, acmeClient)
	}

	// periodically cleanup local certificate files not found on server
	if *clientCleanupEnabled {
		go client.CleanupCertificateFiles(logger, *clientCleanupInterval, *clientConfigPath, acmeClient)
	}

	http.Handle("/metrics", promhttp.Handler())

	runHTTPServer(*serverListenAddress, *serverTLSCertFile, *serverTLSKeyFile, *serverReadTimeout, *serverReadHeaderTimeout)
}

func runHTTPServer(listenAddress, certFile, keyFile string, readTimeout, readHeaderTimeout int) {
	server := &http.Server{
		Addr:              listenAddress,
		ReadTimeout:       time.Duration(readTimeout) * time.Second,
		ReadHeaderTimeout: time.Duration(readHeaderTimeout) * time.Second,
	}
	_ = level.Info(logger).Log("msg", "Client listening on", "address", listenAddress)
	if certFile == "" && keyFile == "" {
		_ = level.Info(logger).Log("msg", "TLS is disabled.", "address", listenAddress)
		if err := server.ListenAndServe(); err != nil {
			_ = level.Error(logger).Log("err", err)
			os.Exit(1)
		}
	} else {
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			_ = level.Error(logger).Log("err", err)
			os.Exit(1)
		}
	}
}
