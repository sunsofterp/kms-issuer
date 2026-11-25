package certmanager

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// caNotAfter is each issuer's CA certificate expiry, for alerting before the
	// copy on devices runs out.
	caNotAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kms_issuer_ca_not_after_timestamp_seconds",
		Help: "When the KMSIssuer's current CA certificate expires (Unix seconds).",
	}, []string{"namespace", "name"})
	// caIssued counts CA certificates made, by reason.
	caIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kms_issuer_ca_certificates_issued_total",
		Help: "CA certificates the controller made, by issuer.",
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
)

func init() {
	metrics.Registry.MustRegister(caNotAfter, caIssued, certificatesIssued, requestsRefused)
}
