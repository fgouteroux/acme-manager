package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	managedCertificate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_certificate_total",
			Help: "Number of managed certificates by issuer and owner",
		},
		[]string{"issuer", "owner"},
	)

	createdCertificate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_certificate_created",
			Help: "Created certificate by issuer, owner and domain, 1 = created, 0 = error",
		},
		[]string{"issuer", "owner", "domain"},
	)

	revokedCertificate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_certificate_revoked",
			Help: "Revoked certificate by issuer, owner and domain, 1 = revoked, 0 = error",
		},
		[]string{"issuer", "owner", "domain"},
	)

	renewedCertificate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_manager_certificate_renewed",
			Help: "Renewed certificate by issuer, owner and domain, 1 = renewed, 0 = error",
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
		[]string{},
	)

	runFailedLocalCmd = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_local_cmd_run_failed_total",
			Help: "Number of failed local cmd runs",
		},
		[]string{},
	)

	getSuccessVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_get_secret_success_total",
			Help: "Number of retrieved vault secrets",
		},
		[]string{},
	)

	putSuccessVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_put_secret_success_total",
			Help: "Number of created/updated vault secrets",
		},
		[]string{},
	)

	deleteSuccessVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_delete_secret_success_total",
			Help: "Number of deleted vault secrets",
		},
		[]string{},
	)

	getFailedVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_get_secret_failed_total",
			Help: "Number of failed vault secret retrievals",
		},
		[]string{},
	)

	putFailedVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_put_secret_failed_total",
			Help: "Number of failed vault secret creations/updates",
		},
		[]string{},
	)

	deleteFailedVaultSecret = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_manager_vault_delete_secret_failed_total",
			Help: "Number of failed vault secret deletions",
		},
		[]string{},
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
)

func IncManagedCertificate(issuer, owner string) {
	managedCertificate.WithLabelValues(issuer, owner).Inc()
}

func DecManagedCertificate(issuer, owner string) {
	managedCertificate.WithLabelValues(issuer, owner).Dec()
}

func SetCreatedCertificate(issuer, owner, domain string, value float64) {
	createdCertificate.WithLabelValues(issuer, owner, domain).Set(value)
}

func SetRevokedCertificate(issuer, owner, domain string, value float64) {
	revokedCertificate.WithLabelValues(issuer, owner, domain).Set(value)
}

func SetRenewedCertificate(issuer, owner, domain string, value float64) {
	renewedCertificate.WithLabelValues(issuer, owner, domain).Set(value)
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
		issuerConfigError,
		httpRequestsTotal,
		httpRequestDuration,
		httpRequestSize,
		httpResponseSize,
		httpRequestsInFlight,
	}

	for _, collector := range collectors {
		_ = prometheus.Register(collector)
	}
}
