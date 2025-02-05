package certstore

import (
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

type CertificateCollector struct {
	Logger log.Logger
}

func (c *CertificateCollector) Describe(_ chan<- *prometheus.Desc) {}

func (c *CertificateCollector) Collect(ch chan<- prometheus.Metric) {
	data, err := AmStore.GetKVRingCert(AmCertificateRingKey, false)
	if err != nil {
		_ = level.Error(c.Logger).Log("err", err)
		return
	}

	for _, cert := range data {
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

func NewCertificateCollector(logger log.Logger) *CertificateCollector {
	return &CertificateCollector{Logger: logger}
}
