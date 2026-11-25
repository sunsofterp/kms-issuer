package certmanager

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// caNotAfter is each issuer's intermediate expiry, for alerting well before a new
	// one must be made.
	caNotAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kms_issuer_intermediate_not_after_timestamp_seconds",
		Help: "When the KMSIssuer's intermediate CA certificate expires (Unix seconds).",
	}, []string{"namespace", "name"})
	// certificatesIssued counts certificates signed, by issuer.
	certificatesIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kms_issuer_certificates_issued_total",
		Help: "Certificates signed for CertificateRequests, by issuer.",
	}, []string{"namespace", "name"})
	// requestsRefused counts requests failed by the issuance policy, by issuer.
	requestsRefused = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kms_issuer_requests_refused_total",
		Help: "CertificateRequests refused by the issuance policy, by issuer.",
	}, []string{"namespace", "name"})
	// rootNotAfter is the pinned root's expiry.
	rootNotAfter = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kms_issuer_root_not_after_timestamp_seconds",
		Help: "When the pinned root CA certificate expires (Unix seconds).",
	})
)

func init() {
	metrics.Registry.MustRegister(caNotAfter, certificatesIssued, requestsRefused, rootNotAfter)
}

// RecordRoot exports the pinned root's expiry.
func RecordRoot(a *Access) {
	rootNotAfter.Set(float64(a.Root().NotAfter.Unix()))
}
