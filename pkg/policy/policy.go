// Package policy decides what the issuer will sign. It builds every issued
// certificate from fields it has checked, never from the request's raw extensions:
// a server certificate, for DNS names inside the issuer's permitted domains only,
// never a CA, for at most the issuer's maximum duration and never past the CA's own
// expiry.
package policy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	// minDuration is the shortest validity a request may ask for (cert-manager's).
	minDuration = time.Hour
	// clockSkew backdates notBefore, for clients whose clocks run slightly behind.
	clockSkew  = 5 * time.Minute
	minRSABits = 2048
	maxRSABits = 8192
	maxDNSName = 253
)

// Usage names, as cert-manager spells them.
const (
	UsageDigitalSignature = "digital signature"
	UsageKeyEncipherment  = "key encipherment"
	UsageServerAuth       = "server auth"
)

// oidSubjectAltName is id-ce-subjectAltName.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// ErrDenied wraps every refusal: the request will never be signed as it is.
var ErrDenied = errors.New("request refused by the issuer's policy")

// Issuer is what the issuer allows.
type Issuer struct {
	// PermittedDNSDomains: every DNS name must equal one or be a subdomain of one.
	PermittedDNSDomains []string
	// AllowWildcards permits names like *.example.internal.
	AllowWildcards bool
	// MaxDuration is the longest validity a request may ask for.
	MaxDuration time.Duration
}

// Request is the part of a cert-manager CertificateRequest the policy looks at.
type Request struct {
	// CSR is the PEM-encoded PKCS#10 request.
	CSR []byte
	// IsCA is the request's spec.isCA.
	IsCA bool
	// Usages is the request's spec.usages (cert-manager names).
	Usages []string
	// Duration is the request's spec.duration; zero means DefaultDuration.
	Duration time.Duration
	// DefaultDuration applies when Duration is zero.
	DefaultDuration time.Duration
}

// Template checks req against iss and returns the certificate to sign and the
// subject's public key. parent is the issuing CA certificate; the result never
// outlives it. Errors wrapping ErrDenied mean the request must be failed for good.
func Template(req *Request, iss *Issuer, parent *x509.Certificate, serial *big.Int, now time.Time) (*x509.Certificate, crypto.PublicKey, error) {
	if req.IsCA {
		return nil, nil, deny("CA certificates are never issued")
	}
	csr, err := parseCSR(req.CSR)
	if err != nil {
		return nil, nil, err
	}
	if err := checkSANTypes(csr); err != nil {
		return nil, nil, err
	}
	if len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 || len(csr.EmailAddresses) > 0 {
		return nil, nil, deny("only DNS names may be requested (no IP addresses, URIs or email addresses)")
	}
	names, err := checkDNSNames(csr.DNSNames, iss)
	if err != nil {
		return nil, nil, err
	}
	commonName := strings.ToLower(csr.Subject.CommonName)
	if commonName != "" && !contains(names, commonName) {
		return nil, nil, deny("the common name %q is not one of the requested DNS names", csr.Subject.CommonName)
	}
	keyUsage, err := checkPublicKey(csr.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	if err := checkUsages(req.Usages); err != nil {
		return nil, nil, err
	}

	duration := req.Duration
	if duration == 0 {
		duration = req.DefaultDuration
	}
	if duration < minDuration {
		return nil, nil, deny("duration %s is shorter than %s", duration, minDuration)
	}
	if iss.MaxDuration <= 0 || duration > iss.MaxDuration {
		return nil, nil, deny("duration %s is longer than the issuer allows (%s)", duration, iss.MaxDuration)
	}
	notBefore := now.Add(-clockSkew).UTC().Truncate(time.Second)
	notAfter := now.Add(duration).UTC().Truncate(time.Second)
	if notAfter.After(parent.NotAfter) {
		notAfter = parent.NotAfter
	}
	if !notAfter.After(now) {
		return nil, nil, fmt.Errorf("the CA certificate expires at %s; nothing can be issued under it", parent.NotAfter)
	}

	cert := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              names,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return cert, csr.PublicKey, nil
}

func deny(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrDenied, fmt.Sprintf(format, args...))
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, deny("spec.request is not a PEM CERTIFICATE REQUEST")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, deny("spec.request has data after the CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, deny("spec.request does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, deny("spec.request's signature is invalid: %v", err)
	}
	return csr, nil
}

// checkSANTypes refuses a subjectAltName extension holding any name type other
// than dNSName, iPAddress, uniformResourceIdentifier or rfc822Name (the parser
// silently drops otherName, directoryName and the rest; refusing beats ignoring).
func checkSANTypes(csr *x509.CertificateRequest) error {
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		input := cryptobyte.String(ext.Value)
		var seq cryptobyte.String
		if !input.ReadASN1(&seq, cbasn1.SEQUENCE) || !input.Empty() {
			return deny("the subjectAltName extension is malformed")
		}
		for !seq.Empty() {
			var tag cbasn1.Tag
			var value cryptobyte.String
			if !seq.ReadAnyASN1(&value, &tag) {
				return deny("the subjectAltName extension is malformed")
			}
			switch tag {
			case cbasn1.Tag(1).ContextSpecific(), // rfc822Name
				cbasn1.Tag(2).ContextSpecific(), // dNSName
				cbasn1.Tag(6).ContextSpecific(), // uniformResourceIdentifier
				cbasn1.Tag(7).ContextSpecific(): // iPAddress
			default:
				return deny("the subjectAltName extension holds a name type other than DNS names")
			}
		}
	}
	return nil
}

func checkDNSNames(requested []string, iss *Issuer) ([]string, error) {
	if len(requested) == 0 {
		return nil, deny("at least one DNS name is required")
	}
	if len(iss.PermittedDNSDomains) == 0 {
		return nil, deny("the issuer permits no DNS domains")
	}
	names := make([]string, 0, len(requested))
	for _, raw := range requested {
		name := strings.ToLower(raw)
		if contains(names, name) {
			continue
		}
		host := name
		if strings.HasPrefix(name, "*.") {
			if !iss.AllowWildcards {
				return nil, deny("wildcard name %q: the issuer does not allow wildcards", raw)
			}
			host = name[2:]
		}
		if !validHostname(host) {
			return nil, deny("%q is not a valid DNS name", raw)
		}
		if !permitted(host, iss.PermittedDNSDomains) {
			return nil, deny("%q is outside the issuer's permitted domains %v", raw, iss.PermittedDNSDomains)
		}
		names = append(names, name)
	}
	return names, nil
}

// permitted reports whether host equals a domain or is a subdomain of one.
func permitted(host string, domains []string) bool {
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// validHostname accepts letters, digits and hyphens in labels of 1-63 characters,
// no leading or trailing hyphen, no empty label, no trailing dot.
func validHostname(host string) bool {
	if host == "" || len(host) > maxDNSName {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// checkPublicKey accepts RSA 2048-8192, ECDSA P-256/P-384/P-521 and Ed25519, and
// returns the key usage a server certificate for that key gets.
func checkPublicKey(pub crypto.PublicKey) (x509.KeyUsage, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < minRSABits || bits > maxRSABits {
			return 0, deny("RSA key of %d bits; %d to %d are accepted", bits, minRSABits, maxRSABits)
		}
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return x509.KeyUsageDigitalSignature, nil
		}
		return 0, deny("ECDSA curve %s is not accepted", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return x509.KeyUsageDigitalSignature, nil
	}
	return 0, deny("public key type %T is not accepted", pub)
}

// checkUsages accepts only what a server certificate needs. The certificate's usages
// come from the key type, not from this list: key encipherment is accepted for any
// key (cert-manager requests it by default) but granted only to RSA keys.
func checkUsages(usages []string) error {
	for _, u := range usages {
		switch u {
		case UsageDigitalSignature, UsageServerAuth, UsageKeyEncipherment:
		default:
			return deny("usage %q is not accepted (only %q, %q and %q)", u,
				UsageDigitalSignature, UsageKeyEncipherment, UsageServerAuth)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
