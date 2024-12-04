package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/joho/godotenv"

	"github.com/go-kit/log/level"
	"github.com/grafana/dskit/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/sirupsen/logrus"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"

	"gopkg.in/yaml.v3"
)

var (
	metricsPath           = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	prefixPath            = kingpin.Flag("web.prefix-path", "Prefix path for all http requests.").Default("").String()
	webConfig             = webflag.AddFlags(kingpin.CommandLine, ":8989")
	configPath            = kingpin.Flag("config-path", "Config path").Default("config.yml").String()
	certificateConfigPath = kingpin.Flag("certificate-config-path", "Certificate config path").Default("certificate.yml").String()
	envConfigPath         = kingpin.Flag("env-config-path", "Environment vars config path").Default(".env").String()

	ringInstanceID             = kingpin.Flag("ring.instance-id", "Instance ID to register in the ring.").String()
	ringInstanceAddr           = kingpin.Flag("ring.instance-addr", "IP address to advertise in the ring. Default is auto-detected.").String()
	ringInstancePort           = kingpin.Flag("ring.instance-port", "Port to advertise in the ring.").Default("7946").Int()
	ringInstanceInterfaceNames = kingpin.Flag("ring.instance-interface-names", "List of network interface names to look up when finding the instance IP address.").String()
	ringJoinMembers            = kingpin.Flag("ring.join-members", "Other cluster members to join.").String()

	checkRenewalInterval           = kingpin.Flag("check-renewal-interval", "Time interval to check if renewal needed").Default("1h").Duration()
	checkConfigInterval            = kingpin.Flag("check-config-interval", "Time interval to check if config file changes").Default("30s").Duration()
	checkCertificateConfigInterval = kingpin.Flag("check-certificate-config-interval", "Time interval to check if certificate config file changes").Default("30s").Duration()
	checkLocalCertificateInterval  = kingpin.Flag("check-local-certificate-interval", "Time interval to check if local certificate changes").Default("5m").Duration()
)

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

	logger := promlog.New(promlogConfig)

	err := godotenv.Load(*envConfigPath)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		os.Exit(1)
	}

	configBytes, err := os.ReadFile(*configPath)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		os.Exit(1)
	}

	var cfg config.Config
	err = yaml.Unmarshal(configBytes, &cfg)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		os.Exit(1)
	}

	config.GlobalConfig = cfg

	err = prometheus.Register(version.NewCollector("acme_manager"))
	if err != nil {
		level.Error(logger).Log("msg", "Error registering version collector", "err", err) // #nosec G104
	}

	level.Info(logger).Log("msg", "Starting acme-manager", "version", version.Info())       // #nosec G104
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext()) // #nosec G104

	http.Handle(*metricsPath, promhttp.Handler())
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
		level.Error(logger).Log("err", err) // #nosec G104
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

	err = certstore.Setup(logger, cfg)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		os.Exit(1)
	}

	vault.VaultClient, err = vault.InitVaultClient(cfg.Storage.Vault)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		os.Exit(1)
	}

	// build the kv store ring or join it then process certificate check-up
	err = certstore.OnStartup(logger, *certificateConfigPath)
	if err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		os.Exit(1)
	}

	// check config file changes
	go certstore.WatchConfigFileChanges(logger, *checkConfigInterval, *configPath)

	// check certificate file changes
	go certstore.WatchCertificateFileChanges(logger, *checkCertificateConfigInterval, *certificateConfigPath)

	// check kv store changes
	go certstore.WatchRingKvStoreChanges(logger)

	// renewal certificate
	go certstore.WatchCertExpiration(logger, *checkRenewalInterval)

	// check local certificate
	go certstore.WatchLocalCertificate(logger, *checkLocalCertificateInterval)

	http.Handle("/", indexHandler("", indexPage))
	http.HandleFunc("/ring/leader", func(w http.ResponseWriter, req *http.Request) {
		leaderHandler(w, req)
	})
	http.HandleFunc("/certificates", func(w http.ResponseWriter, req *http.Request) {
		certificateHandler(w, req)
	})

	http.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, req *http.Request) {
		httpChallengeHandler(w, req)
	})

	server := &http.Server{
		ReadTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if err := web.ListenAndServe(server, webConfig, logger); err != nil {
		level.Error(logger).Log("err", err) // #nosec G104
		os.Exit(1)
	}
}
