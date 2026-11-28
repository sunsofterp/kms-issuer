package certmanager

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// issuerLabels name a KMSIssuer in the per-issuer metrics.
var issuerLabels = []string{"namespace", "name"}

var (
	// caNotAfter is each issuer's intermediate expiry, for alerting well before a new
	// one must be made.
	caNotAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kms_issuer_intermediate_not_after_timestamp_seconds",
		Help: "When the KMSIssuer's intermediate CA certificate expires (Unix seconds).",
	}, issuerLabels)
	// certificatesIssued counts certificates signed, by issuer.
	certificatesIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kms_issuer_certificates_issued_total",
		Help: "Certificates signed for CertificateRequests, by issuer.",
	}, issuerLabels)
	// requestsRefused counts requests failed by the issuance policy, by issuer.
	requestsRefused = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kms_issuer_requests_refused_total",
		Help: "CertificateRequests refused by the issuance policy, by issuer.",
	}, issuerLabels)
	// leavesTruncated is 1 while new certificates are being cut short to end with
	// the intermediate: the intermediate is overdue for renewal.
	leavesTruncated = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kms_issuer_leaves_truncated",
		Help: "1 while the KMSIssuer's intermediate expires sooner than its longest certificate: new certificates are cut short.",
	}, issuerLabels)
	// rootNotAfter is each pinned root's expiry.
	rootNotAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kms_issuer_root_not_after_timestamp_seconds",
		Help: "When each pinned root CA certificate expires (Unix seconds).",
	}, []string{"subject", "sha256"})
)

func init() {
	metrics.Registry.MustRegister(caNotAfter, certificatesIssued, requestsRefused, leavesTruncated, rootNotAfter)
}

// RecordRoots exports each pinned root's expiry, valid now or not (an expired one
// shows as a past timestamp to alert on).
func RecordRoots(a *Access) {
	for _, root := range a.Roots() {
		sum := sha256.Sum256(root.Raw)
		rootNotAfter.WithLabelValues(root.Subject.String(), hex.EncodeToString(sum[:])).Set(float64(root.NotAfter.Unix()))
	}
}
