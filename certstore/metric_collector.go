package certstore

import (
	"math"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/fgouteroux/acme_manager/ring"
)

type CertificateCollector struct {
	Logger log.Logger
}

func (c *CertificateCollector) Describe(_ chan<- *prometheus.Desc) {}

func (c *CertificateCollector) Collect(ch chan<- prometheus.Metric) {
	data, err := AmStore.ListAllCertificates(false)
	if err != nil {
		_ = level.Error(c.Logger).Log("err", err)
		return
	}

	for _, cert := range data {
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
		daysUntilExpiration := float64(math.Round(time.Until(notAfter).Hours() / 24))

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

func NewCertificateCollector(logger log.Logger) *CertificateCollector {
	return &CertificateCollector{Logger: logger}
}


type NodeCollector struct {
	Logger log.Logger
}

func (nc *NodeCollector) Describe(_ chan<- *prometheus.Desc) {}

func (nc *NodeCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			"acme_manager_node_role",
			"Node role, 0 = unknown, 1 = leader, 2 = follower", nil, nil,
		),
		prometheus.GaugeValue,
		nc.getRole(),
	)
}

func NewNodeCollector(logger log.Logger) *NodeCollector {
	return &NodeCollector{Logger: logger}
}

// getRole determines if this node is leader or follower
func (nc *NodeCollector) getRole() float64 {
	isLeader, err := ring.IsLeader(AmStore.RingConfig)
	if err != nil {
		_ = level.Warn(nc.Logger).Log("msg", "Failed to determine role", "err", err)
		return 0
	}

	if isLeader {
		return 1
	}
	return 2
}