package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/joho/godotenv"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/dskit/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/sirupsen/logrus"

	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/client"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/restclient"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"

	_ "github.com/fgouteroux/acme_manager/docs"

	"gopkg.in/yaml.v3"
)

var (
	serverListenAddress     = kingpin.Flag("server.listen-address", "server listen address").Default(":8989").String()
	serverTLSCertFile       = kingpin.Flag("server.tls-cert-file", "server tls certificate file").String()
	serverTLSKeyFile        = kingpin.Flag("server.tls-key-file", "server tls key file").String()
	serverTLSClientCAFile   = kingpin.Flag("server.tls-client-ca-file", "Root certificate authority used to verify client certificates").String()
	serverReadTimeout       = kingpin.Flag("server.http-read-timeout", "Read timeout for entire HTTP request, including headers and body").Default("300").Int()
	serverReadHeaderTimeout = kingpin.Flag("server.http-read-header-timeout", "Read timeout for HTTP request headers").Default("10").Int()

	configPath            = kingpin.Flag("config-path", "Config path").Default("config.yml").String()
	certificateConfigPath = kingpin.Flag("certificate-config-path", "Certificate config path").Default("certificate.yml").String()
	envConfigPath         = kingpin.Flag("env-config-path", "Environment vars config path").Default(".env").String()
	enableAPI             = kingpin.Flag("enable-api", "Enables API mode and disable --certificate-config-path parameter.").Bool()

	ringInstanceID             = kingpin.Flag("ring.instance-id", "Instance ID to register in the ring.").String()
	ringInstanceAddr           = kingpin.Flag("ring.instance-addr", "IP address to advertise in the ring. Default is auto-detected.").String()
	ringInstancePort           = kingpin.Flag("ring.instance-port", "Port to advertise in the ring.").Default("7946").Int()
	ringInstanceInterfaceNames = kingpin.Flag("ring.instance-interface-names", "List of network interface names to look up when finding the instance IP address.").String()
	ringJoinMembers            = kingpin.Flag("ring.join-members", "Other cluster members to join.").String()

	checkRenewalInterval = kingpin.Flag("check-renewal-interval", "Time interval to check if renewal needed").Default("30m").Duration()
	checkConfigInterval  = kingpin.Flag("check-config-interval", "Time interval to check if config file changes").Default("30s").Duration()
	checkTokenInterval   = kingpin.Flag("check-token-interval", "Time interval to check if tokens expired").Default("1m").Duration()

	checkCertificateConfigInterval = kingpin.Flag("check-certificate-config-interval", "Time interval to check if certificate config file changes").Default("30s").Duration()
	checkLocalCertificateInterval  = kingpin.Flag("check-local-certificate-interval", "Time interval to check if local certificate changes").Default("1m").Duration()

	clientMode                 = kingpin.Flag("client", "Enables client mode.").Bool()
	clientManagerURL           = kingpin.Flag("client.manager-url", "Client manager URL").Default("http://localhost:8989/api/v1").Envar("ACME_MANAGER_URL").String()
	clientManagerToken         = kingpin.Flag("client.manager-token", "Client manager token").Envar("ACME_MANAGER_TOKEN").String()
	clientManagerTLSCAFile     = kingpin.Flag("client.tls-ca-file", "Client manager tls ca certificate file").String()
	clientManagerTLSCertFile   = kingpin.Flag("client.tls-cert-file", "Client manager tls certificate file").String()
	clientManagerTLSKeyFile    = kingpin.Flag("client.tls-key-file", "Client manager tls key file").String()
	clientManagerTLSSkipVerify = kingpin.Flag("client.tls-skip-verify", "Client manager tls skip verify").Bool()
	clientConfigPath           = kingpin.Flag("client.config-path", "Client config path").Default("client-config.yml").String()
	clientCheckConfigInterval  = kingpin.Flag("client.check-config-interval", "Time interval to check if client config file changes and to update local certificate file").Default("1m").Duration()

	logger      log.Logger
	proxyClient *http.Client
)

// @title acme manager
// @version 1.0
// @description Manages acme certificate and deploy them on servers
// @contact.name François Gouteroux
// @contact.email francois.gouteroux@gmail.com
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @BasePath /api/v1
// @securityDefinitions.apikey APIKeyAuth
// @in header
// @name X-API-Key
func main() {
	log := logrus.New()
	log.SetReportCaller(true)
	log.SetFormatter(utils.UTCFormatter{Formatter: &logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime: "ts",
			logrus.FieldKeyFile: "caller",
		},
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", fmt.Sprintf("%s:%d", utils.FormatFilePath(f.File), f.Line)
		},
	}})

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("acme-manager"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	lvl, _ := logrus.ParseLevel(promlogConfig.Level.String())
	log.SetLevel(lvl)

	logger = promlog.New(promlogConfig)

	if *clientMode {
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
		)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		// Compare and create/update certificate from config file to remote server
		client.CheckCertificate(logger, *clientConfigPath, acmeClient)

		// check local certificate are up-to-date
		client.CheckAndDeployLocalCertificate(logger, acmeClient)

		go client.WatchCertificate(logger, *clientCheckConfigInterval, *clientConfigPath, acmeClient)

		http.Handle("/metrics", promhttp.Handler())

		runHTTPServer(*serverListenAddress, *serverTLSCertFile, *serverTLSKeyFile, *serverReadTimeout, *serverReadHeaderTimeout)
	}

	err := godotenv.Load(*envConfigPath)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
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

	err = prometheus.Register(version.NewCollector("acme_manager"))
	if err != nil {
		_ = level.Error(logger).Log("msg", "Error registering version collector", "err", err)
	}

	_ = level.Info(logger).Log("msg", "Starting acme-manager", "version", version.Info())
	_ = level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())

	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	indexPage := newIndexPageContent()
	indexPage.AddLinks(metricsWeight, "Certificates", []IndexPageLink{
		{Desc: "Managed certificates", Path: "/certificates"},
	})
	indexPage.AddLinks(metricsWeight, "Metrics", []IndexPageLink{
		{Desc: "Exported metrics", Path: "/metrics"},
	})

	var ringConfig ring.AcmeManagerRing

	ctx := context.Background()
	ringConfig, err = ring.New(*ringInstanceID, *ringInstanceAddr, *ringJoinMembers, *ringInstanceInterfaceNames, *ringInstancePort, logger)
	defer services.StopAndAwaitTerminated(ctx, ringConfig.Memberlistsvc) //nolint:errcheck
	defer services.StopAndAwaitTerminated(ctx, ringConfig.Lifecycler)    //nolint:errcheck
	defer services.StopAndAwaitTerminated(ctx, ringConfig.Client)        //nolint:errcheck

	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	indexPage.AddLinks(ringWeight, "Ring", []IndexPageLink{
		{Desc: "Ring status", Path: "/ring"},
	})
	indexPage.AddLinks(memberlistWeight, "Memberlist", []IndexPageLink{
		{Desc: "Status", Path: "/memberlist"},
	})

	http.Handle("/ring", ringConfig.Lifecycler)
	http.Handle("/memberlist", memberlistStatusHandler("", ringConfig.Memberlistsvc))

	certstore.AmStore = &certstore.CertStore{
		RingConfig: ringConfig,
		Logger:     logger,
	}

	err = certstore.Setup(logger, cfg, version.Version)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	vault.GlobalClient, err = vault.InitClient(cfg.Storage.Vault)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	// build the kv store ring or join it then process certificate check-up
	err = certstore.OnStartup(logger, *certificateConfigPath, *enableAPI)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	if *enableAPI {
		// Init proxy http client used to forward request
		tlsConfig, err := utils.SetTLSConfig(*serverTLSCertFile, *serverTLSKeyFile, *serverTLSClientCAFile, false)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		proxyClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

		// metadata certificate
		http.Handle("GET /api/v1/certificate/metadata", LoggerHandler(certificateMetadataHandler()))

		// certificate
		http.Handle("PUT /api/v1/certificate", LoggerHandler(updateCertificateHandler()))
		http.Handle("POST /api/v1/certificate", LoggerHandler(createCertificateHandler()))
		http.Handle("GET /api/v1/certificate/{issuer}/{domain}", LoggerHandler(getCertificateHandler()))
		http.Handle("DELETE /api/v1/certificate/{issuer}/{domain}", LoggerHandler(revokeCertificateHandler()))

		// token
		http.Handle("PUT /api/v1/token/", LoggerHandler(updateTokenHandler()))
		http.Handle("POST /api/v1/token", LoggerHandler(createTokenHandler()))
		http.Handle("GET /api/v1/token/{id}", LoggerHandler(getTokenHandler()))
		http.Handle("DELETE /api/v1/token/{id}", LoggerHandler(revokeTokenHandler()))

		http.Handle("/tokens", LoggerHandler(tokenListHandler()))

		indexPage.AddLinks(metricsWeight, "Tokens", []IndexPageLink{
			{Desc: "Managed tokens", Path: "/tokens"},
		})
		go certstore.WatchTokenExpiration(logger, *checkTokenInterval)

		// renewal certificate
		go certstore.WatchAPICertExpiration(logger, *checkRenewalInterval)

	} else {
		// check certificate file changes
		go certstore.WatchCertificateFileChanges(logger, *checkCertificateConfigInterval, *certificateConfigPath)

		// check kv store cert changes
		go certstore.WatchRingKvStoreCertChanges(logger)

		// check local certificate
		go certstore.WatchLocalCertificate(logger, *checkLocalCertificateInterval)

		// renewal certificate
		go certstore.WatchCertExpiration(logger, *checkRenewalInterval)
	}

	// check config file changes
	go certstore.WatchConfigFileChanges(logger, *checkConfigInterval, *configPath, version.Version)

	http.Handle("/", indexHandler("", indexPage))
	http.HandleFunc("/ring/leader", func(w http.ResponseWriter, req *http.Request) {
		leaderHandler(w, req)
	})
	http.Handle("/certificates", LoggerHandler(certificateListHandler()))

	http.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, req *http.Request) {
		httpChallengeHandler(w, req)
	})

	http.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	runHTTPServer(*serverListenAddress, *serverTLSCertFile, *serverTLSKeyFile, *serverReadTimeout, *serverReadHeaderTimeout)
}

func runHTTPServer(listenAddress, certFile, keyFile string, readTimeout, readHeaderTimeout int) {
	server := &http.Server{
		Addr:              listenAddress,
		ReadTimeout:       time.Duration(readTimeout) * time.Second,
		ReadHeaderTimeout: time.Duration(readHeaderTimeout) * time.Second,
	}
	_ = level.Info(logger).Log("msg", "Listening on", "address", listenAddress)
	if certFile == "" && keyFile == "" {
		_ = level.Info(logger).Log("msg", "TLS is disabled.", "address", listenAddress)
		if err := server.ListenAndServe(); err != nil {
			_ = level.Error(logger).Log("err", err)
			os.Exit(1)
		}
	} else {
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		}
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			_ = level.Error(logger).Log("err", err)
			os.Exit(1)
		}
	}
}
