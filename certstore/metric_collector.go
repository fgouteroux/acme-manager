package certstore

import (
	"math"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/fgouteroux/acme-manager/ring"
)

type CertificateCollector struct {
	Logger log.Logger
}

func (c *CertificateCollector) Describe(_ chan<- *prometheus.Desc) {}

func (c *CertificateCollector) Collect(ch chan<- prometheus.Metric) {
	data, err := AmStore.ListAllCertificates()
	if err != nil {
		_ = level.Error(c.Logger).Log("err", err)
		return
	}

	for _, cert := range data {
		labels := prometheus.Labels{
			"issuer":     cert.Issuer,
			"owner":      cert.Owner,
			"domain":     cert.Domain,
			"name":       cert.Name,
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

func NewCertificateCollector(logger log.Logger) *CertificateCollector {
	return &CertificateCollector{Logger: logger}
}

// KVCollector reports how many keys the Ring KV store holds per key type.
type KVCollector struct {
	Logger log.Logger
}

func (c *KVCollector) Describe(_ chan<- *prometheus.Desc) {}

// Collect emits one series per key type. Counts include entries that were
// marked for deletion but not yet garbage-collected: the memberlist KV List
// is a raw prefix scan over the local store and never inspects the Deleted
// flag, so tombstones remain visible until ObsoleteEntriesTimeout elapses.
func (c *KVCollector) Collect(ch chan<- prometheus.Metric) {
	desc := prometheus.NewDesc(
		"acme_manager_kv_keys",
		"Number of keys in the ring KV store per key type, including entries marked for deletion but not yet garbage-collected",
		[]string{"type"}, nil,
	)

	// Always report every known type, so a type that legitimately holds no key
	// is reported as 0 rather than disappearing from the scrape.
	for _, kv := range []struct {
		keyType string
		list    func() ([]string, error)
	}{
		{CertificatePrefix, func() ([]string, error) { return AmStore.ListCertificateKVRingKeys(CertificatePrefix + "/") }},
		{TokenPrefix, AmStore.ListTokenKVRingKeys},
		{RateLimitPrefix, func() ([]string, error) { return AmStore.ListRateLimitKVRingKeys(RateLimitPrefix + "/") }},
	} {
		keys, err := kv.list()
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to list kv ring keys", "type", kv.keyType, "err", err)
			continue
		}

		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(len(keys)), kv.keyType)
	}
}

func NewKVCollector(logger log.Logger) *KVCollector {
	return &KVCollector{Logger: logger}
}

type TokenCollector struct {
	Logger log.Logger
}

func (c *TokenCollector) Describe(_ chan<- *prometheus.Desc) {}

func (c *TokenCollector) Collect(ch chan<- prometheus.Metric) {
	data, err := AmStore.ListAllTokens()
	if err != nil {
		_ = level.Error(c.Logger).Log("err", err)
		return
	}

	for key, token := range data {
		// ListAllTokens does not filter tombstones, unlike ListAllCertificates.
		if token.DeletedAt > 0 {
			continue
		}

		tokenID, err := ParseTokenKey(key)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "Failed to parse token key", "key", key, "err", err)
			continue
		}

		daysUntilExpiration, err := tokenExpiryDays(token.Expires)
		if err != nil {
			_ = level.Error(c.Logger).Log("msg", "failed to parse token expiration time", "token_id", tokenID, "err", err)
			continue
		}

		// The token hash is credential material and must never be exposed here.
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"acme_manager_token_expiry",
				"Token expiry in days with id, username and scope. Non-expiring tokens report +Inf.", nil,
				prometheus.Labels{
					"id":       tokenID,
					"username": token.Username,
					"scope":    strings.Join(token.Scope, ","),
					"expires":  token.Expires,
				},
			),
			prometheus.GaugeValue,
			daysUntilExpiration,
		)
	}
}

func NewTokenCollector(logger log.Logger) *TokenCollector {
	return &TokenCollector{Logger: logger}
}

// tokenExpiryDays returns the number of days until the token expires, or +Inf
// for a token that never expires.
func tokenExpiryDays(expires string) (float64, error) {
	if expires == "Never" {
		return math.Inf(1), nil
	}

	// Define the layout for the date string
	layout := "2006-01-02 15:04:05 -0700 MST"

	notAfter, err := time.Parse(layout, expires)
	if err != nil {
		return 0, err
	}

	return math.Trunc(time.Until(notAfter).Hours() / 24), nil
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
