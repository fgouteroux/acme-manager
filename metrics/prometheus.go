package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	managedCertificate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_managed_certificates",
			Help: "Current number of managed certificates by issuer, owner, domain and name",
		},
		[]string{"issuer", "owner", "domain", "name"},
	)

	certificateOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_certificate_operations_total",
			Help: "Total number of certificate operations by issuer, owner, domain, name, operation and status",
		},
		[]string{"issuer", "owner", "domain", "name", "operation", "status"},
	)

	certificateRenewalsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_certificate_renewals",
			Help: "Current renewal count per certificate as persisted in the Ring KV store (survives restarts and leader changes)",
		},
		[]string{"issuer", "owner", "domain", "name"},
	)

	localCertificateOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_local_certificate_operations_total",
			Help: "Total number of local certificate operations by issuer and operation",
		},
		[]string{"issuer", "operation"},
	)

	localCmdRunTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_local_cmd_run_total",
			Help: "Total number of local cmd runs by command and status",
		},
		[]string{"command", "status"},
	)

	vaultSecretOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_secret_operations_total",
			Help: "Total number of vault secret operations by operation and status",
		},
		[]string{"secret_type", "operation", "status"},
	)

	certificateConfigError = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_certificate_config_error",
			Help: "1 if there was an error opening or reading the certificate config file, 0 otherwise",
		},
		[]string{},
	)

	configError = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_config_error",
			Help: "1 if there was an error opening or reading the config file, 0 otherwise",
		},
		[]string{},
	)

	issuerConfigError = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_issuer_config_error",
			Help: "1 if there was an error with issuer config, 0 otherwise",
		},
		[]string{"issuer"},
	)

	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_http_requests_total",
			Help: "Total number of HTTP requests by method, path and status code",
		},
		[]string{"method", "path", "status_code"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "acme_manager_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	httpRequestsInFlight = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "acme_manager_http_requests_in_flight",
			Help: "Current number of HTTP requests being processed",
		},
	)

	rateLimitBlockedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_rate_limit_blocked_total",
			Help: "Total certificate requests blocked by rate limiting",
		},
		[]string{"issuer", "owner", "operation"},
	)
)

func IncManagedCertificate(issuer, owner, domain, name string) {
	managedCertificate.WithLabelValues(issuer, owner, domain, name).Inc()
}

func DecManagedCertificate(issuer, owner, domain, name string) {
	managedCertificate.WithLabelValues(issuer, owner, domain, name).Dec()
}

func IncCertificateCreated(issuer, owner, domain, name string) {
	certificateOperationsTotal.WithLabelValues(issuer, owner, domain, name, "create", "success").Inc()
}

func IncCertificateCreationError(issuer, owner, domain, name string) {
	certificateOperationsTotal.WithLabelValues(issuer, owner, domain, name, "create", "error").Inc()
}

func IncRevokedCertificate(issuer, owner, domain, name string) {
	certificateOperationsTotal.WithLabelValues(issuer, owner, domain, name, "revoke", "success").Inc()
}

func IncRevokedCertificateErrors(issuer, owner, domain, name string) {
	certificateOperationsTotal.WithLabelValues(issuer, owner, domain, name, "revoke", "error").Inc()
}

func SetCertificateRenewed(issuer, owner, domain, name string, count int64) {
	certificateRenewalsTotal.WithLabelValues(issuer, owner, domain, name).Set(float64(count))
}

func IncCertificateRenewalError(issuer, owner, domain, name string) {
	certificateOperationsTotal.WithLabelValues(issuer, owner, domain, name, "renew", "error").Inc()
}

// InitCertificateErrorMetrics initializes the renew/error series to 0 at startup
// so that increase() works correctly on the first renewal error for a known cert.
func InitCertificateErrorMetrics(issuer, owner, domain, name string) {
	certificateOperationsTotal.WithLabelValues(issuer, owner, domain, name, "renew", "error").Add(0)
}

// DeleteCertificateMetrics removes all metric series for the given label set.
// Call this when a cert's issuer or domain changes so stale series don't linger.
func DeleteCertificateMetrics(issuer, owner, domain, name string) {
	managedCertificate.DeleteLabelValues(issuer, owner, domain, name)
	certificateOperationsTotal.DeleteLabelValues(issuer, owner, domain, name, "renew", "error")
	certificateRenewalsTotal.DeleteLabelValues(issuer, owner, domain, name)
}

func IncCreatedLocalCertificate(issuer string) {
	localCertificateOperationsTotal.WithLabelValues(issuer, "created").Inc()
}

func IncDeletedLocalCertificate(issuer string) {
	localCertificateOperationsTotal.WithLabelValues(issuer, "deleted").Inc()
}

func IncRunSuccessLocalCmd(command string) {
	localCmdRunTotal.WithLabelValues(command, "success").Inc()
}

func IncRunFailedLocalCmd(command string) {
	localCmdRunTotal.WithLabelValues(command, "failed").Inc()
}

func IncGetSuccessVaultSecret(secretType string) {
	vaultSecretOperationsTotal.WithLabelValues(secretType, "get", "success").Inc()
}

func IncPutSuccessVaultSecret(secretType string) {
	vaultSecretOperationsTotal.WithLabelValues(secretType, "put", "success").Inc()
}

func IncDeleteSuccessVaultSecret(secretType string) {
	vaultSecretOperationsTotal.WithLabelValues(secretType, "delete", "success").Inc()
}

func IncGetFailedVaultSecret(secretType string) {
	vaultSecretOperationsTotal.WithLabelValues(secretType, "get", "failed").Inc()
}

func IncPutFailedVaultSecret(secretType string) {
	vaultSecretOperationsTotal.WithLabelValues(secretType, "put", "failed").Inc()
}

func IncDeleteFailedVaultSecret(secretType string) {
	vaultSecretOperationsTotal.WithLabelValues(secretType, "delete", "failed").Inc()
}

func SetCertificateConfigError(value float64) {
	certificateConfigError.WithLabelValues().Set(value)
}

func SetConfigError(value float64) {
	configError.WithLabelValues().Set(value)
}

func SetIssuerConfigError(issuer string, value float64) {
	issuerConfigError.WithLabelValues(issuer).Set(value)
}

func RecordHTTPRequest(method, path, statusCode string, duration float64) {
	httpRequestsTotal.WithLabelValues(method, path, statusCode).Inc()
	httpRequestDuration.WithLabelValues(method, path).Observe(duration)
}

func IncHTTPRequestsInFlight() {
	httpRequestsInFlight.Inc()
}

func DecHTTPRequestsInFlight() {
	httpRequestsInFlight.Dec()
}

func IncRateLimitBlocked(owner, issuer, operation string) {
	rateLimitBlockedTotal.WithLabelValues(issuer, owner, operation).Inc()
}

func init() {
	collectors := []prometheus.Collector{
		managedCertificate,
		certificateOperationsTotal,
		certificateRenewalsTotal,
		localCertificateOperationsTotal,
		localCmdRunTotal,
		vaultSecretOperationsTotal,
		certificateConfigError,
		configError,
		issuerConfigError,
		httpRequestsTotal,
		httpRequestDuration,
		httpRequestsInFlight,
		rateLimitBlockedTotal,
	}

	for _, collector := range collectors {
		_ = prometheus.Register(collector)
	}
}
