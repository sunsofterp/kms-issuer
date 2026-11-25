package kmsca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

// ParseCertificatePEM parses exactly one PEM CERTIFICATE block and nothing else.
// Anything before or after it (another certificate, junk) is refused, so what is
// stored can never smuggle extra trust material into what is handed out.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM CERTIFICATE")
	}
	if len(block.Headers) > 0 {
		return nil, errors.New("PEM headers are not allowed")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("data after the CERTIFICATE block")
	}
	if prefix := bytes.TrimSpace(data[:bytes.Index(data, []byte("-----BEGIN"))]); len(prefix) > 0 {
		return nil, errors.New("data before the CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// EncodeCertificatePEM re-encodes a parsed certificate.
func EncodeCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// ExpectedCA is what a CA certificate made by this controller must be.
type ExpectedCA struct {
	PublicKey           crypto.PublicKey
	CommonName          string
	PermittedDNSDomains []string
	Now                 time.Time
}

// ValidateCA returns an error unless cert is exactly a CA certificate this
// controller would have made for expected: self-signed by the KMS key, path length
// 0, cert-sign and CRL-sign only, no extended key usages, critical name constraints
// limiting DNS, URI and email names to the permitted domains and excluding every IP
// address, and valid now. A certificate planted in status by anyone else fails.
func ValidateCA(cert *x509.Certificate, expected ExpectedCA) error {
	switch {
	case cert == nil:
		return errors.New("no certificate")
	case !publicKeysEqual(cert.PublicKey, expected.PublicKey):
		return errors.New("not for the KMS key")
	case cert.CheckSignatureFrom(cert) != nil:
		return errors.New("not self-signed by the KMS key")
	case !cert.BasicConstraintsValid || !cert.IsCA:
		return errors.New("not a CA certificate")
	case !cert.MaxPathLenZero || cert.MaxPathLen != 0:
		return errors.New("path length is not 0")
	case cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign:
		return errors.New("key usage is not exactly cert sign and CRL sign")
	case len(cert.ExtKeyUsage) > 0 || len(cert.UnknownExtKeyUsage) > 0:
		return errors.New("extended key usages present")
	case cert.Subject.CommonName != expected.CommonName:
		return errors.New("common name differs")
	case !cert.PermittedDNSDomainsCritical:
		return errors.New("name constraints are not critical")
	case !sameDomainSet(cert.PermittedDNSDomains, expected.PermittedDNSDomains):
		return errors.New("permitted DNS domains differ")
	case !sameDomainSet(cert.PermittedURIDomains, expected.PermittedDNSDomains):
		return errors.New("permitted URI domains differ")
	case !sameDomainSet(cert.PermittedEmailAddresses, expected.PermittedDNSDomains):
		return errors.New("permitted email domains differ")
	case len(cert.PermittedIPRanges) > 0 || !excludesAllIPs(cert.ExcludedIPRanges):
		return errors.New("IP addresses are not all excluded")
	case len(cert.ExcludedDNSDomains)+len(cert.ExcludedURIDomains)+len(cert.ExcludedEmailAddresses) > 0:
		return errors.New("unexpected excluded name constraints")
	case expected.Now.Before(cert.NotBefore) || !expected.Now.Before(cert.NotAfter):
		return fmt.Errorf("not valid now (%s to %s)", cert.NotBefore, cert.NotAfter)
	}
	return nil
}

func sameDomainSet(a, b []string) bool {
	norm := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, d := range list {
			out = append(out, strings.ToLower(strings.TrimSuffix(d, ".")))
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(norm(a), norm(b))
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
