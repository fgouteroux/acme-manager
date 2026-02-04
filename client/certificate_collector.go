package client

import (
	"math"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type CertificateCollector struct{}

func (c *CertificateCollector) Describe(_ chan<- *prometheus.Desc) {}

func (c *CertificateCollector) Collect(ch chan<- prometheus.Metric) {
	for _, cert := range certificates {
		labels := prometheus.Labels{
			"issuer":     cert.Issuer,
			"owner":      cert.Owner,
			"domain":     cert.Domain,
			"expires":    cert.Expires,
			"encryption": cert.Encryption,
			"serial":     cert.Serial,
		}

		for _, item := range strings.Split(cert.Labels, ",") {
			label := strings.Split(item, "=")
			if len(label) == 2 {
				labels[label[0]] = label[1]
			}
		}

		// Define the layout for the date string
		layout := "2006-01-02 15:04:05 -0700 MST"

		// Parse the string into a time.Time object
		notAfter, _ := time.Parse(layout, cert.Expires)

		// Calculate the number of days until expiration
		daysUntilExpiration := math.Trunc(time.Until(notAfter).Hours() / 24)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"acme_manager_certificate_expiry",
				"Certificate expiry with issuer, owner, domain", nil, labels,
			),
			prometheus.GaugeValue,
			daysUntilExpiration,
		)
	}
}

func NewCertificateCollector() *CertificateCollector {
	return &CertificateCollector{}
}
