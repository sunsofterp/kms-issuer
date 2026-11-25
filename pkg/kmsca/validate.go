package kmsca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ParseCertificatePEM parses exactly one PEM CERTIFICATE block and nothing else.
// Anything before or after it (another certificate, junk) is refused, so what is
// stored can never smuggle extra trust material into what is handed out.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	start := bytes.Index(data, []byte("-----BEGIN"))
	if start < 0 {
		return nil, errors.New("not a PEM CERTIFICATE")
	}
	if len(bytes.TrimSpace(data[:start])) > 0 {
		return nil, errors.New("data before the CERTIFICATE block")
	}
	block, rest := pem.Decode(data[start:])
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM CERTIFICATE")
	}
	if len(block.Headers) > 0 {
		return nil, errors.New("PEM headers are not allowed")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("data after the CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// EncodeCertificatePEM re-encodes a parsed certificate.
func EncodeCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// ValidateRoot returns an error unless root is a usable root for this CA: a
// self-signed CA certificate allowed to sign intermediates (path length 1),
// cert-sign key usage, critical name constraints with at least one DNS domain and
// no IP address, and valid at now.
func ValidateRoot(root *x509.Certificate, now time.Time) error {
	switch {
	case root == nil:
		return errors.New("no root certificate")
	case !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil:
		return errors.New("not self-signed")
	case !root.BasicConstraintsValid || !root.IsCA:
		return errors.New("not a CA certificate")
	case root.MaxPathLen != 1:
		return errors.New("path length is not 1")
	case root.KeyUsage&x509.KeyUsageCertSign == 0:
		return errors.New("no cert-sign key usage")
	}
	if err := checkConstraints(root); err != nil {
		return err
	}
	return checkValidity(root, now)
}

// ExpectedIntermediate is what an issuer's intermediate must match.
type ExpectedIntermediate struct {
	// Root is the operator's pinned root.
	Root *x509.Certificate
	// PublicKey is the issuer's KMS key.
	PublicKey crypto.PublicKey
	// AllowedDomains bound the intermediate's name constraints (the operator's
	// ceilings).
	AllowedDomains []string
	Now            time.Time
}

// ValidateIntermediate returns an error unless cert is an intermediate this
// controller may sign under: for the issuer's KMS key, issued and signed by the
// pinned root (and verifying as a chain to it), a CA with path length 0, cert-sign
// key usage, no extended key usages, critical name constraints with every DNS, URI
// and email domain inside the allowed domains and every IP address excluded, and
// valid now.
func ValidateIntermediate(cert *x509.Certificate, expected ExpectedIntermediate) error {
	switch {
	case cert == nil:
		return errors.New("no intermediate certificate")
	case expected.Root == nil:
		return errors.New("no root certificate")
	case !publicKeysEqual(cert.PublicKey, expected.PublicKey):
		return errors.New("not for the issuer's KMS key")
	case publicKeysEqual(cert.PublicKey, expected.Root.PublicKey):
		return errors.New("the issuing key is the root key")
	case !bytes.Equal(cert.RawIssuer, expected.Root.RawSubject) || cert.CheckSignatureFrom(expected.Root) != nil:
		return errors.New("not issued by the pinned root")
	case !cert.BasicConstraintsValid || !cert.IsCA:
		return errors.New("not a CA certificate")
	case !cert.MaxPathLenZero || cert.MaxPathLen != 0:
		return errors.New("path length is not 0")
	case cert.KeyUsage&x509.KeyUsageCertSign == 0:
		return errors.New("no cert-sign key usage")
	case cert.KeyUsage&^(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature) != 0:
		return errors.New("unexpected key usages")
	case len(cert.ExtKeyUsage) > 0 || len(cert.UnknownExtKeyUsage) > 0:
		return errors.New("extended key usages present")
	}
	if err := checkConstraints(cert); err != nil {
		return err
	}
	for _, list := range [][]string{cert.PermittedDNSDomains, cert.PermittedURIDomains, cert.PermittedEmailAddresses} {
		for _, d := range list {
			if !WithinDomains(d, expected.AllowedDomains) {
				return fmt.Errorf("name constraint %q is outside the allowed domains %v", d, expected.AllowedDomains)
			}
		}
	}
	if err := checkValidity(cert, expected.Now); err != nil {
		return err
	}
	// Full path validation as clients do it, root constraints included.
	roots := x509.NewCertPool()
	roots.AddCert(expected.Root)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: expected.Now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("does not verify to the pinned root: %w", err)
	}
	return nil
}

// checkConstraints requires critical name constraints: at least one permitted DNS
// domain, URI and email limited, no permitted IP range and every IP excluded.
func checkConstraints(cert *x509.Certificate) error {
	switch {
	case !cert.PermittedDNSDomainsCritical:
		return errors.New("name constraints are missing or not critical")
	case len(cert.PermittedDNSDomains) == 0:
		return errors.New("no permitted DNS domain")
	case len(cert.PermittedURIDomains) == 0 || len(cert.PermittedEmailAddresses) == 0:
		return errors.New("URI and email names are not limited")
	case len(cert.PermittedIPRanges) > 0 || !excludesAllIPs(cert.ExcludedIPRanges):
		return errors.New("IP addresses are not all excluded")
	}
	return nil
}

func checkValidity(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return fmt.Errorf("not valid now (%s to %s)", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// WithinDomains reports whether d (or the host part of an email constraint) equals
// one of domains or is a subdomain of one. A leading dot (a constraint meaning
// "subdomains only") is inside the domain it qualifies.
func WithinDomains(d string, domains []string) bool {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(d, "."), "."))
	if i := strings.LastIndex(d, "@"); i >= 0 {
		d = d[i+1:]
	}
	if d == "" {
		return false
	}
	for _, c := range domains {
		c = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(c, "."), "."))
		if c != "" && (d == c || strings.HasSuffix(d, "."+c)) {
			return true
		}
	}
	return false
}

func excludesAllIPs(ranges []*net.IPNet) bool {
	var v4, v6 bool
	for _, r := range ranges {
		ones, bits := r.Mask.Size()
		if ones != 0 {
			continue
		}
		switch bits {
		case 32:
			v4 = true
		case 128:
			v6 = true
		}
	}
	return v4 && v6
}
