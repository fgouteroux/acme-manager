package metrics

import "github.com/prometheus/client_golang/prometheus"

var managedCertificate = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "acme_manager_certificate_total",
		Help: "Number of managed certificates by issuer and owner",
	},
	[]string{"issuer", "owner"},
)

var createdCertificate = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_certificate_created_total",
		Help: "Number of created certificates by issuer and owner",
	},
	[]string{"issuer", "owner"},
)

var revokedCertificate = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_certificate_revoked_total",
		Help: "Number of revoked certificates by issuer and owner",
	},
	[]string{"issuer", "owner"},
)

var renewedCertificate = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_certificate_renewed_total",
		Help: "Number of renewed certificates by issuer and owner",
	},
	[]string{"issuer", "owner"},
)

var createdLocalCertificate = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_local_certificate_created_total",
		Help: "Number of created local certificates by issuer",
	},
	[]string{"issuer"},
)

var deletedLocalCertificate = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_local_certificate_deleted_total",
		Help: "Number of deleted local certificates by issuer",
	},
	[]string{"issuer"},
)

var runSuccessLocalCmd = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_local_cmd_run_success_total",
		Help: "Number of success local cmd run",
	},
	[]string{},
)

var runFailedLocalCmd = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_local_cmd_run_failed_total",
		Help: "Number of failed local cmd run",
	},
	[]string{},
)

var getSuccessVaultSecret = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_vault_get_secret_success_total",
		Help: "Number of retrieved vault secrets",
	},
	[]string{},
)

var putSuccessVaultSecret = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_vault_put_secret_success_total",
		Help: "Number of created/updated vault secrets",
	},
	[]string{},
)

var deleteSuccessVaultSecret = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_vault_delete_secret_success_total",
		Help: "Number of created vault secrets",
	},
	[]string{},
)

var getFailedVaultSecret = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_vault_get_secret_failed_total",
		Help: "Number of created vault secrets",
	},
	[]string{},
)

var putFailedVaultSecret = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_vault_put_secret_failed_total",
		Help: "Number of deleted vault secrets",
	},
	[]string{},
)

var deleteFailedVaultSecret = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_vault_delete_secret_failed_total",
		Help: "Number of created vault secrets",
	},
	[]string{},
)

var certificateConfigReload = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "acme_manager_certificate_config_reload",
		Help: "Number of certificate config file reload",
	},
	[]string{},
)

var certificateConfigError = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "acme_manager_certificate_config_error",
		Help: "1 if there was an error opening or reading the certificate config file, 0 otherwise",
	},
	[]string{},
)

var configReload = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "acme_manager_config_reload",
		Help: "Number of config file reload",
	},
	[]string{},
)

var configError = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "acme_manager_config_error",
		Help: "1 if there was an error opening or reading the config file, 0 otherwise",
	},
	[]string{},
)

func SetManagedCertificate(issuer, owner string, value float64) {
	managedCertificate.WithLabelValues(issuer, owner).Set(value)
}

func IncManagedCertificate(issuer, owner string) {
	managedCertificate.WithLabelValues(issuer, owner).Inc()
}

func DecManagedCertificate(issuer, owner string) {
	managedCertificate.WithLabelValues(issuer, owner).Dec()
}

func IncCreatedCertificate(issuer, owner string) {
	createdCertificate.WithLabelValues(issuer, owner).Inc()
}

func IncRevokedCertificate(issuer, owner string) {
	revokedCertificate.WithLabelValues(issuer, owner).Inc()
}

func IncRenewedCertificate(issuer, owner string) {
	renewedCertificate.WithLabelValues(issuer, owner).Inc()
}

func IncCreatedLocalCertificate(issuer string) {
	createdLocalCertificate.WithLabelValues(issuer).Inc()
}

func IncDeletedLocalCertificate(issuer string) {
	deletedLocalCertificate.WithLabelValues(issuer).Inc()
}

func IncRunSuccessLocalCmd() {
	runSuccessLocalCmd.WithLabelValues().Inc()
}

func IncRunFailedLocalCmd() {
	runFailedLocalCmd.WithLabelValues().Inc()
}

func IncGetSuccessVaultSecret() {
	getSuccessVaultSecret.WithLabelValues().Inc()
}

func IncPutSuccessVaultSecret() {
	putSuccessVaultSecret.WithLabelValues().Inc()
}

func IncDeleteSuccessVaultSecret() {
	deleteSuccessVaultSecret.WithLabelValues().Inc()
}

func IncGetFailedVaultSecret() {
	getFailedVaultSecret.WithLabelValues().Inc()
}

func IncPutFailedVaultSecret() {
	putFailedVaultSecret.WithLabelValues().Inc()
}

func IncDeleteFailedVaultSecret() {
	deleteFailedVaultSecret.WithLabelValues().Inc()
}

func IncCertificateConfigReload() {
	certificateConfigReload.WithLabelValues().Inc()
}

func SetCertificateConfigError(value float64) {
	certificateConfigError.WithLabelValues().Set(value)
}

func IncConfigReload() {
	configReload.WithLabelValues().Inc()
}

func SetConfigError(value float64) {
	configError.WithLabelValues().Set(value)
}

func init() {
	collectors := []prometheus.Collector{
		managedCertificate,
		createdCertificate,
		revokedCertificate,
		renewedCertificate,
		createdLocalCertificate,
		deletedLocalCertificate,
		runSuccessLocalCmd,
		runFailedLocalCmd,
		getSuccessVaultSecret,
		putSuccessVaultSecret,
		deleteSuccessVaultSecret,
		getFailedVaultSecret,
		putFailedVaultSecret,
		deleteFailedVaultSecret,
		certificateConfigReload,
		certificateConfigError,
		configReload,
		configError,
	}

	for _, collector := range collectors {
		_ = prometheus.Register(collector)
	}
}
