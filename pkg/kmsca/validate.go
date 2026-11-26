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

	"github.com/sunsofterp/kms-issuer/v5/pkg/domains"
)

// pemCertificate is a PEM certificate block's type.
const pemCertificate = "CERTIFICATE"

// ParseCertificatePEM parses exactly one PEM CERTIFICATE block and nothing else.
// Anything before or after it (another certificate, junk) is refused, so what is
// stored can never smuggle extra trust material into what is handed out.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	certs, err := ParseCertificatesPEM(data)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("%d certificates where exactly one is expected", len(certs))
	}
	return certs[0], nil
}

// ParseCertificatesPEM parses one or more PEM CERTIFICATE blocks and nothing else:
// no other block type, no headers, no data before, between or after them.
func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := bytes.TrimSpace(data)
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, errors.New("data outside the CERTIFICATE blocks")
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != pemCertificate {
			return nil, errors.New("not a PEM CERTIFICATE")
		}
		if len(block.Headers) > 0 {
			return nil, errors.New("PEM headers are not allowed")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		rest = bytes.TrimSpace(rest)
	}
	if len(certs) == 0 {
		return nil, errors.New("not a PEM CERTIFICATE")
	}
	return certs, nil
}

// EncodeCertificatePEM re-encodes a parsed certificate.
func EncodeCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemCertificate, Bytes: cert.Raw})
}

// ValidateRoot returns an error unless root is a usable root for this CA: a
// self-signed CA certificate allowed to sign intermediates (path length 1),
// cert-sign key usage, critical name constraints of valid domains with no IP
// address, and valid at now.
func ValidateRoot(root *x509.Certificate, now time.Time) error {
	if err := ValidateRootStructure(root); err != nil {
		return err
	}
	return checkValidity(root, now)
}

// ValidateRootStructure is ValidateRoot without the validity period: what makes a
// certificate a root of this CA at all, expired or not.
func ValidateRootStructure(root *x509.Certificate) error {
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
	for _, d := range root.PermittedDNSDomains {
		if err := ValidConstraintDomain(d); err != nil {
			return err
		}
	}
	// URI and email constraints too: each must name a valid domain.
	for _, c := range slices.Concat(root.PermittedURIDomains, root.PermittedEmailAddresses) {
		if err := ValidConstraintDomain(ConstraintDomain(c)); err != nil {
			return fmt.Errorf("URI or email constraint: %w", err)
		}
	}
	return nil
}

// RootConstraintDomains are the domains every name constraint of a root covers
// (DNS, URI and email).
func RootConstraintDomains(root *x509.Certificate) []string {
	var ds []string
	for _, c := range slices.Concat(root.PermittedDNSDomains, root.PermittedURIDomains, root.PermittedEmailAddresses) {
		ds = append(ds, ConstraintDomain(c))
	}
	return ds
}

// ExpectedIntermediate is what an issuer's intermediate must match.
type ExpectedIntermediate struct {
	// Roots are the operator's pinned roots valid now: the intermediate must chain
	// to one.
	Roots []*x509.Certificate
	// OtherRoots are pinned roots not valid now (expired, or not yet valid): never
	// chained to, but, like Roots, their keys are refused as the issuing key.
	OtherRoots []*x509.Certificate
	// PublicKey is the issuer's KMS key.
	PublicKey crypto.PublicKey
	// AllowedDomains bound the intermediate's name constraints (the operator's
	// ceilings).
	AllowedDomains []string
	// MaxDuration bounds the intermediate's validity (0: MaxIntermediateDuration).
	MaxDuration time.Duration
	Now         time.Time
}

// ValidateIntermediate returns the pinned root cert chains to, or an error unless
// cert is an intermediate this controller may sign under: for the issuer's KMS key
// and no root's, issued and signed by a pinned root (and verifying as a chain to it),
// a CA with path length 0, cert-sign key usage, the server-auth extended key usage
// and no other, critical name constraints with every DNS, URI and email domain
// inside both the allowed domains and the root's, every IP address excluded, a name
// different from the root's, valid now, and no longer-lived than the maximum.
func ValidateIntermediate(cert *x509.Certificate, expected *ExpectedIntermediate) (*x509.Certificate, error) {
	root, err := issuingRoot(cert, expected)
	if err != nil {
		return nil, err
	}
	err = checkIntermediateShape(cert, root, expected.MaxDuration)
	if err != nil {
		return nil, err
	}
	err = checkConstraints(cert)
	if err != nil {
		return nil, err
	}
	err = checkConstraintsWithin(cert, expected.AllowedDomains, root)
	if err != nil {
		return nil, err
	}
	err = checkValidity(cert, expected.Now)
	if err != nil {
		return nil, err
	}
	// Full path validation as clients do it, root constraints included.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: expected.Now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return nil, fmt.Errorf("does not verify to the pinned root: %w", err)
	}
	return root, nil
}

// issuingRoot returns the pinned root that issued and signed cert, after checking
// cert is for the issuer's KMS key and no root's (pinned or other).
func issuingRoot(cert *x509.Certificate, expected *ExpectedIntermediate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, errors.New("no intermediate certificate")
	}
	if len(expected.Roots) == 0 {
		return nil, errors.New("no root certificate")
	}
	if !publicKeysEqual(cert.PublicKey, expected.PublicKey) {
		return nil, errors.New("not for the issuer's KMS key")
	}
	for _, r := range expected.OtherRoots {
		if publicKeysEqual(cert.PublicKey, r.PublicKey) {
			return nil, errors.New("the issuing key is a root key")
		}
	}
	var root *x509.Certificate
	for _, r := range expected.Roots {
		if publicKeysEqual(cert.PublicKey, r.PublicKey) {
			return nil, errors.New("the issuing key is a root key")
		}
		if bytes.Equal(cert.RawIssuer, r.RawSubject) && cert.CheckSignatureFrom(r) == nil {
			root = r
		}
	}
	if root == nil {
		return nil, errors.New("not issued by a pinned root")
	}
	return root, nil
}

// checkIntermediateShape requires a CA with path length 0, a name different from
// the root's, cert-sign key usage (CRL sign and digital signature also allowed),
// exactly the server-auth extended key usage, and a validity no longer than
// maxDuration (0 or more than MaxIntermediateDuration: MaxIntermediateDuration).
func checkIntermediateShape(cert, root *x509.Certificate, maxDuration time.Duration) error {
	if maxDuration <= 0 || maxDuration > MaxIntermediateDuration {
		maxDuration = MaxIntermediateDuration
	}
	switch {
	case bytes.Equal(cert.RawSubject, root.RawSubject) || cert.Subject.CommonName == root.Subject.CommonName:
		return errors.New("the intermediate's name is the root's")
	case !cert.BasicConstraintsValid || !cert.IsCA:
		return errors.New("not a CA certificate")
	case !cert.MaxPathLenZero || cert.MaxPathLen != 0:
		return errors.New("path length is not 0")
	case cert.KeyUsage&x509.KeyUsageCertSign == 0:
		return errors.New("no cert-sign key usage")
	case cert.KeyUsage&^(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature) != 0:
		return errors.New("unexpected key usages")
	case !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) || len(cert.UnknownExtKeyUsage) > 0:
		return errors.New("extended key usage is not exactly server auth")
	case cert.NotAfter.Sub(cert.NotBefore) > maxDuration:
		return fmt.Errorf("valid for %s, longer than the %s an intermediate may be", cert.NotAfter.Sub(cert.NotBefore), maxDuration)
	}
	return nil
}

// checkConstraintsWithin requires every DNS, URI and email constraint domain of
// cert inside both the allowed domains and the root's DNS constraints.
func checkConstraintsWithin(cert *x509.Certificate, allowed []string, root *x509.Certificate) error {
	for _, list := range [][]string{cert.PermittedDNSDomains, cert.PermittedURIDomains, cert.PermittedEmailAddresses} {
		for _, d := range list {
			if !WithinDomains(d, allowed) {
				return fmt.Errorf("name constraint %q is outside the allowed domains %v", d, allowed)
			}
			if !WithinDomains(d, root.PermittedDNSDomains) {
				return fmt.Errorf("name constraint %q is outside the root's %v", d, root.PermittedDNSDomains)
			}
		}
	}
	return nil
}

// errNotYetValid marks a certificate whose validity hasn't started.
var errNotYetValid = errors.New("not valid yet")

// IsNotYetValid reports whether err is a certificate not yet valid.
func IsNotYetValid(err error) bool { return errors.Is(err, errNotYetValid) }

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
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w (from %s)", errNotYetValid, cert.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(cert.NotAfter) {
		return fmt.Errorf("expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// WithinDomains reports whether d (or the host part of an email constraint) equals
// one of domains or is a subdomain of one. A leading dot (a constraint meaning
// "subdomains only") is inside the domain it qualifies.
func WithinDomains(d string, permitted []string) bool {
	cs := make([]string, 0, len(permitted))
	for _, c := range permitted {
		cs = append(cs, ConstraintDomain(c))
	}
	return domains.Within(ConstraintDomain(d), cs)
}

// ConstraintDomain is the domain a name constraint entry covers: a URI constraint's
// leading dot ("subdomains of") and an email constraint's mailbox are dropped.
func ConstraintDomain(c string) string {
	if i := strings.LastIndex(c, "@"); i >= 0 {
		c = c[i+1:]
	}
	return strings.TrimPrefix(c, ".")
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
