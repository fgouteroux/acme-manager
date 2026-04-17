package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	managedCertificate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_certificate_total",
			Help: "Number of managed certificates by issuer, owner and domain",
		},
		[]string{"issuer", "owner", "domain"},
	)

	certificateCreationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_certificate_creations_total",
			Help: "Total number of successfully created certificates by issuer, owner and domain",
		},
		[]string{"issuer", "owner", "domain"},
	)

	certificateCreationErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_certificate_creation_errors_total",
			Help: "Total number of certificate creation errors by issuer, owner and domain",
		},
		[]string{"issuer", "owner", "domain"},
	)

	revokedCertificateTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_certificate_revoked_total",
			Help: "Total number of successfully revoked certificates by issuer, owner and domain",
		},
		[]string{"issuer", "owner", "domain"},
	)

	revokedCertificateErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_certificate_revoked_errors_total",
			Help: "Total number of certificate revocation errors by issuer, owner and domain",
		},
		[]string{"issuer", "owner", "domain"},
	)

	certificateRenewalsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_certificate_renewals_total",
			Help: "Total number of successfully renewed certificates by issuer, owner and domain (persisted in Ring KV, survives restarts and leader changes)",
		},
		[]string{"issuer", "owner", "domain"},
	)

	certificateRenewalErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_certificate_renewal_errors_total",
			Help: "Total number of certificate renewal errors by issuer, owner and domain",
		},
		[]string{"issuer", "owner", "domain"},
	)

	createdLocalCertificate = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_local_certificate_created_total",
			Help: "Number of created local certificates by issuer",
		},
		[]string{"issuer"},
	)

	deletedLocalCertificate = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_local_certificate_deleted_total",
			Help: "Number of deleted local certificates by issuer",
		},
		[]string{"issuer"},
	)

	runSuccessLocalCmd = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_local_cmd_run_success_total",
			Help: "Number of successful local cmd runs",
		},
		[]string{"command"},
	)

	runFailedLocalCmd = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_local_cmd_run_failed_total",
			Help: "Number of failed local cmd runs",
		},
		[]string{"command"},
	)

	getSuccessVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_get_secret_success_total",
			Help: "Number of retrieved vault secrets",
		},
		[]string{"secret_type"},
	)

	putSuccessVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_put_secret_success_total",
			Help: "Number of created/updated vault secrets",
		},
		[]string{"secret_type"},
	)

	deleteSuccessVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_delete_secret_success_total",
			Help: "Number of deleted vault secrets",
		},
		[]string{"secret_type"},
	)

	getFailedVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_get_secret_failed_total",
			Help: "Number of failed vault secret retrievals",
		},
		[]string{"secret_type"},
	)

	putFailedVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_put_secret_failed_total",
			Help: "Number of failed vault secret creations/updates",
		},
		[]string{"secret_type"},
	)

	deleteFailedVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_delete_secret_failed_total",
			Help: "Number of failed vault secret deletions",
		},
		[]string{"secret_type"},
	)

	certificateConfigReload = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_certificate_config_reload_total",
			Help: "Total number of certificate config file reloads",
		},
		[]string{},
	)

	certificateConfigError = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_certificate_config_error",
			Help: "1 if there was an error opening or reading the certificate config file, 0 otherwise",
		},
		[]string{},
	)

	configReload = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_config_reload_total",
			Help: "Total number of config file reloads",
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
		[]string{"method", "path", "status_code"},
	)

	httpRequestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "acme_manager_http_request_size_bytes",
			Help:    "HTTP request size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path"},
	)

	httpResponseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "acme_manager_http_response_size_bytes",
			Help:    "HTTP response size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
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
		[]string{"owner", "issuer", "domain", "operation"},
	)
)

func IncManagedCertificate(issuer, owner, domain string) {
	managedCertificate.WithLabelValues(issuer, owner, domain).Inc()
}

func DecManagedCertificate(issuer, owner, domain string) {
	managedCertificate.WithLabelValues(issuer, owner, domain).Dec()
}

func IncCertificateCreated(issuer, owner, domain string) {
	certificateCreationsTotal.WithLabelValues(issuer, owner, domain).Inc()
}

func IncCertificateCreationError(issuer, owner, domain string) {
	certificateCreationErrorsTotal.WithLabelValues(issuer, owner, domain).Inc()
}

func IncRevokedCertificate(issuer, owner, domain string) {
	revokedCertificateTotal.WithLabelValues(issuer, owner, domain).Inc()
}

func IncRevokedCertificateErrors(issuer, owner, domain string) {
	revokedCertificateErrorsTotal.WithLabelValues(issuer, owner, domain).Inc()
}

func SetCertificateRenewed(issuer, owner, domain string, count int64) {
	certificateRenewalsTotal.WithLabelValues(issuer, owner, domain).Set(float64(count))
}

func IncCertificateRenewalError(issuer, owner, domain string) {
	certificateRenewalErrorsTotal.WithLabelValues(issuer, owner, domain).Inc()
}

// InitCertificateErrorMetrics initializes renewal error counter to 0 at startup
// so that increase() works correctly on the first renewal error for a known domain.
// Creation errors are NOT pre-initialized: the cert doesn't exist in the KV ring yet
// when a creation fails, so label values are unknown at startup.
func InitCertificateErrorMetrics(issuer, owner, domain string) {
	certificateRenewalErrorsTotal.WithLabelValues(issuer, owner, domain).Add(0)
}

func IncCreatedLocalCertificate(issuer string) {
	createdLocalCertificate.WithLabelValues(issuer).Inc()
}

func IncDeletedLocalCertificate(issuer string) {
	deletedLocalCertificate.WithLabelValues(issuer).Inc()
}

func IncRunSuccessLocalCmd(command string) {
	runSuccessLocalCmd.WithLabelValues(command).Inc()
}

func IncRunFailedLocalCmd(command string) {
	runFailedLocalCmd.WithLabelValues(command).Inc()
}

func IncGetSuccessVaultSecret(secretType string) {
	getSuccessVaultSecret.WithLabelValues(secretType).Inc()
}

func IncPutSuccessVaultSecret(secretType string) {
	putSuccessVaultSecret.WithLabelValues(secretType).Inc()
}

func IncDeleteSuccessVaultSecret(secretType string) {
	deleteSuccessVaultSecret.WithLabelValues(secretType).Inc()
}

func IncGetFailedVaultSecret(secretType string) {
	getFailedVaultSecret.WithLabelValues(secretType).Inc()
}

func IncPutFailedVaultSecret(secretType string) {
	putFailedVaultSecret.WithLabelValues(secretType).Inc()
}

func IncDeleteFailedVaultSecret(secretType string) {
	deleteFailedVaultSecret.WithLabelValues(secretType).Inc()
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

func SetIssuerConfigError(issuer string, value float64) {
	issuerConfigError.WithLabelValues(issuer).Set(value)
}

func RecordHTTPRequest(method, path, statusCode string, duration float64, requestSize, responseSize int) {
	httpRequestsTotal.WithLabelValues(method, path, statusCode).Inc()
	httpRequestDuration.WithLabelValues(method, path, statusCode).Observe(duration)
	if requestSize > 0 {
		httpRequestSize.WithLabelValues(method, path).Observe(float64(requestSize))
	}
	if responseSize > 0 {
		httpResponseSize.WithLabelValues(method, path).Observe(float64(responseSize))
	}
}

func IncHTTPRequestsInFlight() {
	httpRequestsInFlight.Inc()
}

func DecHTTPRequestsInFlight() {
	httpRequestsInFlight.Dec()
}

func IncRateLimitBlocked(owner, issuer, domain, operation string) {
	rateLimitBlockedTotal.WithLabelValues(owner, issuer, domain, operation).Inc()
}

func init() {
	collectors := []prometheus.Collector{
		managedCertificate,
		certificateCreationsTotal,
		certificateCreationErrorsTotal,
		revokedCertificateTotal,
		revokedCertificateErrorsTotal,
		certificateRenewalsTotal,
		certificateRenewalErrorsTotal,
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
		issuerConfigError,
		httpRequestsTotal,
		httpRequestDuration,
		httpRequestSize,
		httpResponseSize,
		httpRequestsInFlight,
		rateLimitBlockedTotal,
	}

	for _, collector := range collectors {
		_ = prometheus.Register(collector)
	}
}
