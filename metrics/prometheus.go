package metrics

import "github.com/prometheus/client_golang/prometheus"

var managedCertificate = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "acme_manager_certificate_total",
		Help: "Number of managed certificates by issuer",
	},
	[]string{"issuer"},
)

var createdCertificate = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_certificate_created_total",
		Help: "Number of created certificates by issuer",
	},
	[]string{"issuer"},
)

var revokedCertificate = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_certificate_revoked_total",
		Help: "Number of revoked certificates by issuer",
	},
	[]string{"issuer"},
)

var renewedCertificate = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "acme_manager_certificate_renewed_total",
		Help: "Number of renewed certificates by issuer",
	},
	[]string{"issuer"},
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

func SetManagedCertificate(issuer string, value float64) {
	managedCertificate.WithLabelValues(issuer).Set(value)
}

func IncManagedCertificate(issuer string) {
	managedCertificate.WithLabelValues(issuer).Inc()
}

func DecManagedCertificate(issuer string) {
	managedCertificate.WithLabelValues(issuer).Dec()
}

func IncCreatedCertificate(issuer string) {
	createdCertificate.WithLabelValues(issuer).Inc()
}

func IncRevokedCertificate(issuer string) {
	revokedCertificate.WithLabelValues(issuer).Inc()
}

func IncRenewedCertificate(issuer string) {
	renewedCertificate.WithLabelValues(issuer).Inc()
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

func init() {
	prometheus.Register(managedCertificate)
	prometheus.Register(createdCertificate)
	prometheus.Register(revokedCertificate)
	prometheus.Register(renewedCertificate)
	prometheus.Register(createdLocalCertificate)
	prometheus.Register(deletedLocalCertificate)
	prometheus.Register(runSuccessLocalCmd)
	prometheus.Register(runFailedLocalCmd)

	// vault metrics
	prometheus.Register(getSuccessVaultSecret)
	prometheus.Register(putSuccessVaultSecret)
	prometheus.Register(deleteSuccessVaultSecret)
	prometheus.Register(getFailedVaultSecret)
	prometheus.Register(putFailedVaultSecret)
	prometheus.Register(deleteFailedVaultSecret)
}
