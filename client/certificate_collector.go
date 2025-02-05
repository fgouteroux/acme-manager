package client

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type CertificateCollector struct{}

func (c *CertificateCollector) Describe(_ chan<- *prometheus.Desc) {}

func (c *CertificateCollector) Collect(ch chan<- prometheus.Metric) {
	for _, cert := range certificates {
		labels := prometheus.Labels{
			"issuer":  cert.Issuer,
			"owner":   cert.Owner,
			"domain":  cert.Domain,
			"expires": cert.Expires,
		}

		for _, item := range strings.Split(cert.Labels, ",") {
			label := strings.Split(item, "=")
			if len(label) == 2 {
				labels[label[0]] = label[1]
			}
		}

		value := 1.0
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"acme_manager_certificate_info",
				"Certificate info with issuer, owner, domain", nil, labels,
			),
			prometheus.GaugeValue,
			value,
		)
	}
}

func NewCertificateCollector() *CertificateCollector {
	return &CertificateCollector{}
}
