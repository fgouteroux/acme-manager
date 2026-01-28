package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/dskit/flagext"
	"github.com/grafana/dskit/services"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/sirupsen/logrus"

	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/fgouteroux/acme-manager/api"
	"github.com/fgouteroux/acme-manager/certstore"
	"github.com/fgouteroux/acme-manager/config"
	"github.com/fgouteroux/acme-manager/ring"
	"github.com/fgouteroux/acme-manager/storage/vault"
	"github.com/fgouteroux/acme-manager/utils"

	_ "github.com/fgouteroux/acme-manager/docs"

	"gopkg.in/yaml.v3"
)

var (
	// Logging flags
	logLevel  = flag.String("log.level", "info", "Only log messages with the given severity or above. One of: [debug, info, warn, error].")
	logFormat = flag.String("log.format", "logfmt", "Output format of log messages. One of: [logfmt, json].")

	// Server flags
	serverListenAddress     = flag.String("server.listen-address", ":8989", "Server listen address.")
	serverTLSCertFile       = flag.String("server.tls-cert-file", "", "Server tls certificate file.")
	serverTLSKeyFile        = flag.String("server.tls-key-file", "", "Server tls key file.")
	serverTLSClientCAFile   = flag.String("server.tls-client-ca-file", "", "Root certificate authority used to verify client certificates.")
	serverReadTimeout       = flag.Int("server.http-read-timeout", 300, "Read timeout for entire HTTP request, including headers and body.")
	serverReadHeaderTimeout = flag.Int("server.http-read-header-timeout", 10, "Read timeout for HTTP request headers.")

	// Config flags
	configPath    = flag.String("config-path", "config.yml", "Config path.")
	envConfigPath = flag.String("env-config-path", ".env", "Environment vars config path.")

	// Check interval flags
	checkRenewalInterval = flag.Duration("check-renewal-interval", 30*time.Minute, "Time interval to check if certificate renewal needed.")
	checkConfigInterval  = flag.Duration("check-config-interval", 30*time.Second, "Time interval to check if config file changes.")
	checkTokenInterval   = flag.Duration("check-token-interval", 1*time.Minute, "Time interval to check if tokens expired.")
	checkIssuerInterval  = flag.Duration("check-issuer-interval", 10*time.Minute, "Time interval to check issuer health.")

	// Ring configuration - ALL ring flags automatically registered
	ringConfig = &ring.Config{}

	// Cleanup flags
	cleanup                      = flag.Bool("cleanup", false, "Enables cleanup in vault and CA Issuers.")
	cleanupInterval              = flag.Duration("cleanup.interval", 1*time.Hour, "Time interval to scan vault secret certificates and cleanup if needed.")
	cleanupCertExpDays           = flag.Int("cleanup.cert-expire-days", 10, "Number of days before old certificate expires to revoke and delete vault secret version.")
	cleanupCertRevokeLastVersion = flag.Bool("cleanup.cert-revoke-last-version", false, "Revoke last certificate version and delete vault secret version.")

	// Help flags
	showVersion = flag.Bool("version", false, "Show version information")

	logger log.Logger
)

// Track which flags are "advanced" (memberlist specific) vs "common"
var advancedFlags = make(map[string]bool)
var commonFlagNames = []string{
	"help", "help-all", "version",
	"log.level", "log.format",
	"server.listen-address", "server.tls-cert-file", "server.tls-key-file", "server.tls-client-ca-file",
	"server.http-read-timeout", "server.http-read-header-timeout",
	"config-path", "env-config-path",
	"check-renewal-interval", "check-config-interval", "check-token-interval", "check-issuer-interval",
	"ring.instance-id", "ring.instance-addr", "ring.instance-port", "ring.join-members",
	"cleanup", "cleanup.interval", "cleanup.cert-expire-days", "cleanup.cert-revoke-last-version",
}

const ChallengePath = "/.well-known/acme-challenge/"
const RingFlagPrefix = "ring."

func init() {
	// Initialize ring config with defaults
	flagext.DefaultValues(&ringConfig.MemberlistKV)

	// Create a set of common flag names for easy lookup
	commonFlagsSet := make(map[string]bool)
	for _, name := range commonFlagNames {
		commonFlagsSet[name] = true
	}

	// Register ring flags with "ring." prefix
	// This will create all the detailed memberlist flags automatically
	ringConfig.RegisterFlagsWithPrefix(flag.CommandLine, RingFlagPrefix)

	// Mark all flags that start with "ring.memberlist." as advanced
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "ring.memberlist.") {
			advancedFlags[f.Name] = true
		} else if !commonFlagsSet[f.Name] {
			// Any other flags not in our common list are also advanced
			advancedFlags[f.Name] = true
		}
	})
}

// printFlags prints flags to stdout with option to show all or only common flags
func printFlags(showAll bool) {
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		// Skip advanced flags if showAll is false
		if !showAll && advancedFlags[f.Name] {
			return
		}

		fmt.Fprintf(os.Stdout, "  -%s", f.Name)
		name, usage := flag.UnquoteUsage(f)
		if len(name) > 0 {
			fmt.Fprintf(os.Stdout, " %s", name)
		}

		fmt.Fprintf(os.Stdout, "\n	%s", usage)
		// Default value handling
		if f.DefValue != "" {
			if f.DefValue != "false" { // Don't show default for boolean false
				fmt.Fprintf(os.Stdout, " (default %q)", f.DefValue)
			}
		}
		fmt.Fprintf(os.Stdout, "\n")
	})
}

// @title						acme manager server
// @version					1.0
// @description				ACME Manager Server - Manages ACME certificates in cluster mode
// @contact.name				François Gouteroux
// @contact.email				francois.gouteroux@gmail.com
// @license.name				Apache 2.0
// @license.url				http://www.apache.org/licenses/LICENSE-2.0.html
// @BasePath					/api/v1
// @securityDefinitions.apikey	APIKeyAuth
// @in							header
// @name						X-API-Key
func main() {
	// Custom usage function that shows different help based on --help-all flag
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "\nACME Manager Server - Manages ACME certificates in cluster mode\n")
		fmt.Fprintf(os.Stdout, "Version: %s\n\n", version.Info())

		// Check if --help-all was requested
		showAllFlags := false
		for _, arg := range os.Args[1:] {
			if arg == "--help-all" || arg == "-help-all" {
				showAllFlags = true
				break
			}
		}

		if showAllFlags {
			fmt.Fprintf(os.Stdout, "All flags (including advanced memberlist options):\n")
			printFlags(true) // Show all flags
		} else {
			fmt.Fprintf(os.Stdout, "Flags:\n")
			printFlags(false) // Show only common flags
			fmt.Fprintf(os.Stdout, "\nFor all flags including advanced memberlist configuration options, use: --help-all\n")
		}
	}

	// Check for help flags BEFORE parsing to avoid config file loading
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "-help" || arg == "--help" {
			flag.Usage()
			os.Exit(0)
		}
		if arg == "-help-all" || arg == "--help-all" {
			flag.Usage()
			os.Exit(0)
		}
	}

	// Parse flags
	flag.Parse()

	// Handle version flag
	if *showVersion {
		fmt.Println(version.Print("acme-manager-server"))
		os.Exit(0)
	}

	// Setup all loggers (go-kit, logrus, and lego slog)
	var logrusLogger *logrus.Logger
	logger, logrusLogger = utils.SetupLoggers(*logLevel, *logFormat)

	// Load environment and config
	err := godotenv.Load(*envConfigPath)
	if err != nil {
		_ = level.Debug(logger).Log("msg", "env config file not found", "path", *envConfigPath)
	}

	configBytes, err := os.ReadFile(*configPath)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	var cfg config.Config
	err = yaml.Unmarshal(configBytes, &cfg)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	config.GlobalConfig = cfg

	err = prometheus.Register(versioncollector.NewCollector("acme_manager_server"))
	if err != nil {
		_ = level.Error(logger).Log("msg", "Error registering version collector", "err", err)
	}

	_ = level.Info(logger).Log("msg", "Starting acme-manager-server", "version", version.Info())
	_ = level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())

	http.Handle("/metrics", MetricsHandler(promhttp.Handler()))
	http.Handle("/static/", MetricsHandler(http.FileServer(http.FS(staticFiles))))

	indexPage := newIndexPageContent()
	indexPage.AddLinks(certificateWeight, "Certificates", []IndexPageLink{
		{Desc: "Managed certificates", Path: "/certificates"},
	})
	indexPage.AddLinks(tokenWeight, "Tokens", []IndexPageLink{
		{Desc: "Managed tokens", Path: "/tokens"},
	})
	if config.GlobalConfig.Common.RateLimitEnabled {
		indexPage.AddLinks(rateLimitWeight, "Rate Limits", []IndexPageLink{
			{Desc: "Rate limits", Path: "/ratelimits"},
		})
	}
	indexPage.AddLinks(metricsWeight, "Metrics", []IndexPageLink{
		{Desc: "Exported metrics", Path: "/metrics"},
	})
	indexPage.AddLinks(swaggerWeight, "Swagger", []IndexPageLink{
		{Desc: "Swagger UI", Path: "/swagger"},
	})

	ctx := context.Background()

	// Use the new ring configuration with all the memberlist flags!
	amring, err := ring.NewWithConfig(*ringConfig, logger, flag.CommandLine, RingFlagPrefix)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	// Setup graceful shutdown
	// Create a channel to receive OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create a context that will be cancelled on shutdown
	shutdownCtx, shutdownCancel := context.WithCancel(ctx)
	defer shutdownCancel()

	// Start shutdown handler in a goroutine
	go func() {
		sig := <-sigChan
		_ = level.Info(logger).Log("msg", "Received shutdown signal", "signal", sig.String())

		// Log the current KeepInstanceInTheRingOnShutdown setting
		_ = level.Info(logger).Log("msg", "Graceful shutdown initiated",
			"keep_instance_in_ring", ringConfig.KeepInstanceInTheRingOnShutdown)

		shutdownCancel()
	}()

	// Defer cleanup - this will execute when main function exits
	defer func() {
		_ = level.Info(logger).Log("msg", "Stopping services...")

		// Stop services in reverse order of startup
		// The order matters for graceful shutdown

		// 1. Stop the ring client first
		if err := services.StopAndAwaitTerminated(ctx, amring.Client); err != nil {
			_ = level.Error(logger).Log("msg", "Error stopping ring client", "err", err)
		} else {
			_ = level.Info(logger).Log("msg", "Ring client stopped")
		}

		// 2. Stop the lifecycler
		if err := services.StopAndAwaitTerminated(ctx, amring.Lifecycler); err != nil {
			_ = level.Error(logger).Log("msg", "Error stopping lifecycler", "err", err)
		} else {
			_ = level.Info(logger).Log("msg", "Lifecycler stopped",
				"kept_in_ring", ringConfig.KeepInstanceInTheRingOnShutdown)
		}

		// 3. Finally stop the memberlist service
		if err := services.StopAndAwaitTerminated(ctx, amring.Memberlistsvc); err != nil {
			_ = level.Error(logger).Log("msg", "Error stopping memberlist service", "err", err)
		} else {
			_ = level.Info(logger).Log("msg", "Memberlist service stopped")
		}

		_ = level.Info(logger).Log("msg", "All services stopped gracefully")
	}()

	indexPage.AddLinks(ringWeight, "Ring", []IndexPageLink{
		{Desc: "Ring status", Path: "/ring"},
	})
	indexPage.AddLinks(memberlistWeight, "Memberlist", []IndexPageLink{
		{Desc: "Status", Path: "/memberlist"},
	})

	http.Handle("/ring", MetricsHandler(amring.Lifecycler))
	http.Handle("/memberlist", MetricsHandler(memberlistStatusHandler("", amring.Memberlistsvc)))

	certstore.AmStore = &certstore.CertStore{
		RingConfig: amring,
		Logger:     logger,
	}

	err = certstore.Setup(logger, logrusLogger, config.GlobalConfig, version.Version)
	if err != nil {
		os.Exit(1)
	}

	vault.GlobalClient, err = vault.InitClient(config.GlobalConfig.Storage.Vault, logrusLogger)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	// build the kv store ring or join it then process certificate check-up
	err = certstore.OnStartup(logger)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	// Init proxy http client used to forward request
	tlsConfig, err := utils.SetTLSConfig(*serverTLSCertFile, *serverTLSKeyFile, *serverTLSClientCAFile, false)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}
	proxyClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	// API routes
	http.Handle("GET /api/v1/certificate/metadata", LoggerHandler(api.CertificateMetadataHandler(logger, proxyClient)))
	http.Handle("PUT /api/v1/certificate", LoggerHandler(api.UpdateCertificateHandler(logger, proxyClient)))
	http.Handle("POST /api/v1/certificate", LoggerHandler(api.CreateCertificateHandler(logger, proxyClient)))
	http.Handle("GET /api/v1/certificate/{issuer}/{domain}", LoggerHandler(api.GetCertificateHandler(logger, proxyClient)))
	http.Handle("DELETE /api/v1/certificate/{issuer}/{domain}", LoggerHandler(api.DeleteCertificateHandler(logger, proxyClient)))

	http.Handle("PUT /api/v1/token", LoggerHandler(api.UpdateTokenHandler(logger, proxyClient)))
	http.Handle("POST /api/v1/token", LoggerHandler(api.CreateTokenHandler(logger, proxyClient)))
	http.Handle("GET /api/v1/token/{id}", LoggerHandler(api.GetTokenHandler(logger)))
	http.Handle("DELETE /api/v1/token/{id}", LoggerHandler(api.RevokeTokenHandler(logger, proxyClient)))

	// check token expired
	go certstore.WatchTokenExpiration(logger, *checkTokenInterval)

	// renewal certificate
	go certstore.WatchCertExpiration(logger, *checkRenewalInterval)

	// check config file changes
	go certstore.WatchConfigFileChanges(logger, logrusLogger, *checkConfigInterval, *configPath, version.Version)

	go certstore.WatchIssuerHealth(logger, logrusLogger, *checkIssuerInterval, version.Version)

	// rate limit cleanup (only if enabled)
	go certstore.WatchRateLimitCleanup(logger, 1*time.Hour)

	if *cleanup {
		go certstore.Cleanup(logger, *cleanupInterval, *cleanupCertExpDays, *cleanupCertRevokeLastVersion)
	}

	http.Handle("/", MetricsHandler(indexHandler("", indexPage)))
	http.Handle("/ring/leader", MetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		leaderHandler(w, req)
	})))
	http.Handle("/certificates", LoggerHandler(certificateListHandler()))
	http.Handle("/tokens", LoggerHandler(tokenListHandler()))
	http.Handle("/ratelimits", LoggerHandler(rateLimitListHandler()))

	http.Handle(ChallengePath, MetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		httpChallengeHandler(w, req)
	})))

	http.Handle("/swagger/", MetricsHandler(http.HandlerFunc(httpSwagger.WrapHandler)))
	http.Handle("/health", MetricsHandler(http.HandlerFunc(healthHandler)))

	// Start HTTP server in a goroutine so we can handle shutdown signals
	server := &http.Server{
		Addr:              *serverListenAddress,
		ReadTimeout:       time.Duration(*serverReadTimeout) * time.Second,
		ReadHeaderTimeout: time.Duration(*serverReadHeaderTimeout) * time.Second,
	}

	// Configure TLS if certificates are provided
	if *serverTLSCertFile != "" && *serverTLSKeyFile != "" {
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		}
	}

	// Start server in goroutine
	go func() {
		_ = level.Info(logger).Log("msg", "Server starting", "address", *serverListenAddress)

		var err error
		if *serverTLSCertFile != "" && *serverTLSKeyFile != "" {
			_ = level.Info(logger).Log("msg", "TLS enabled")
			err = server.ListenAndServeTLS(*serverTLSCertFile, *serverTLSKeyFile)
		} else {
			_ = level.Info(logger).Log("msg", "TLS disabled")
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			_ = level.Error(logger).Log("msg", "Server failed", "err", err)
			os.Exit(1)
		}
	}()

	_ = level.Info(logger).Log("msg", "Server started successfully. Press Ctrl+C to gracefully shutdown.")

	// Wait for shutdown signal
	<-shutdownCtx.Done()

	_ = level.Info(logger).Log("msg", "Shutdown signal received, initiating graceful shutdown...")

	// Shutdown HTTP server with timeout
	shutdownTimeout := 30 * time.Second
	serverShutdownCtx, serverCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer serverCancel()

	if err := server.Shutdown(serverShutdownCtx); err != nil {
		_ = level.Error(logger).Log("msg", "Server shutdown error", "err", err)
	} else {
		_ = level.Info(logger).Log("msg", "HTTP server stopped gracefully")
	}

	// Services will be stopped by the defer statements above
	_ = level.Info(logger).Log("msg", "Graceful shutdown completed")
}
