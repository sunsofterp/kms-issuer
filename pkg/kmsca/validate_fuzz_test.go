package kmsca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sunsofterp/kms-issuer/v5/pkg/domains"
)

const (
	ldhDomain        = "a-b.internal"
	underscoreDomain = "ex_ample.internal"
	fuzzHours        = int64(90 * 24)
	certSignCRL      = uint16(x509.KeyUsageCertSign | x509.KeyUsageCRLSign)
)

// splitList is s split on commas, or nil for "".
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// fuzzIntermediate is the intermediate the fuzzer's choices describe.
type fuzzIntermediate struct {
	cn, dnsName, dnsConstraints, uriConstraints, emailConstraints string
	critical, isCA, excludeV4, excludeV6, maxPathLenZero          bool
	clientAuth, unknownEKU                                        bool
	maxPathLen                                                    int8
	keyUsage                                                      uint16
	hours, startHours                                             int64
}

func (p *fuzzIntermediate) template() *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:                big.NewInt(2),
		Subject:                     pkix.Name{CommonName: p.cn},
		NotBefore:                   vtNow.Add(time.Duration(p.startHours) * time.Hour),
		BasicConstraintsValid:       true,
		IsCA:                        p.isCA,
		MaxPathLen:                  int(p.maxPathLen),
		MaxPathLenZero:              p.maxPathLenZero,
		KeyUsage:                    x509.KeyUsage(p.keyUsage),
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PermittedDNSDomainsCritical: p.critical,
		PermittedDNSDomains:         splitList(p.dnsConstraints),
		PermittedURIDomains:         splitList(p.uriConstraints),
		PermittedEmailAddresses:     splitList(p.emailConstraints),
		DNSNames:                    splitList(p.dnsName),
	}
	tmpl.NotAfter = tmpl.NotBefore.Add(time.Duration(p.hours) * time.Hour)
	if p.excludeV4 {
		tmpl.ExcludedIPRanges = append(tmpl.ExcludedIPRanges, &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)})
	}
	if p.excludeV6 {
		tmpl.ExcludedIPRanges = append(tmpl.ExcludedIPRanges, &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)})
	}
	if p.clientAuth {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if p.unknownEKU {
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
	}
	return tmpl
}

// checkAcceptedShape fails t unless cert has the shape ValidateIntermediate's
// contract promises, stated independently of its checks.
func checkAcceptedShape(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	switch {
	case !cert.IsCA || !cert.MaxPathLenZero || cert.MaxPathLen != 0:
		t.Fatal("accepted: not a CA with path length 0")
	case cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.KeyUsage&^(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature) != 0:
		t.Fatalf("accepted: key usage %b", cert.KeyUsage)
	case len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(cert.UnknownExtKeyUsage) > 0:
		t.Fatal("accepted: extended key usage is not exactly server auth")
	case !cert.PermittedDNSDomainsCritical || len(cert.PermittedDNSDomains) == 0 || len(cert.PermittedURIDomains) == 0 || len(cert.PermittedEmailAddresses) == 0:
		t.Fatal("accepted: names not fully constrained")
	case len(cert.PermittedIPRanges) > 0 || !excludesAllIPs(cert.ExcludedIPRanges):
		t.Fatal("accepted: IP addresses not all excluded")
	}
}

// checkAcceptedNameAndValidity fails t unless cert's name differs from the root's
// and it is valid now and no longer-lived than allowed.
func checkAcceptedNameAndValidity(t *testing.T, cert, root *x509.Certificate, now time.Time) {
	t.Helper()
	if cert.Subject.CommonName == root.Subject.CommonName {
		t.Fatal("accepted: the root's name")
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.NotAfter.Sub(cert.NotBefore) > MaxIntermediateDuration {
		t.Fatal("accepted: not valid now, or too long")
	}
}

// checkAcceptedConstraints fails t unless every constraint of cert is inside the
// allowed domains and the root's.
func checkAcceptedConstraints(t *testing.T, cert, root *x509.Certificate, allowed []string) {
	t.Helper()
	for _, list := range [][]string{cert.PermittedDNSDomains, cert.PermittedURIDomains, cert.PermittedEmailAddresses} {
		for _, c := range list {
			if !domains.Within(ConstraintDomain(c), allowed) || !domains.Within(ConstraintDomain(c), root.PermittedDNSDomains) {
				t.Fatalf("accepted: constraint %q outside the allowed domains", c)
			}
		}
	}
}

// checkLeafOutsideRefused fails t if a leaf signed under cert for a name outside
// the allowed domains verifies, as a client would check it.
func checkLeafOutsideRefused(t *testing.T, cert, root *x509.Certificate, issuingKey crypto.Signer, now time.Time) {
	t.Helper()
	name := "x." + vtOther
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafCert := vtSign(t, leaf, cert, vtKey(t).Public(), issuingKey)
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(cert)
	if _, err := leafCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: now, DNSName: name}); err == nil {
		t.Fatal("accepted an intermediate under which a leaf outside the allowed domains verifies")
	}
}

// FuzzValidateIntermediate signs intermediates whose names, constraints, usages,
// path length and validity come from the fuzzer, under a pinned root, and checks
// that whatever ValidateIntermediate accepts is what its contract promises: an
// intermediate a client would refuse to trust for any name outside the allowed
// domains.
func FuzzValidateIntermediate(f *testing.F) {
	rootKey, issuingKey := vtKey(f), vtKey(f)
	root := vtRoot(f, rootKey, "Root", vtDomain)
	f.Add("Issuing", "", vtDomain, vtDomain, vtDomain, true, true, true, true, int8(0), true, certSignCRL, false, false, fuzzHours, int64(-1))
	f.Add("Issuing", "", vtSubDomain, vtOther, vtDomain, true, true, true, true, int8(0), true, uint16(x509.KeyUsageCertSign), false, false, int64(30*24), int64(-1))
	f.Add("Root", "Other", vtDomain, vtDomain, vtDomain, true, true, true, true, int8(0), true, uint16(x509.KeyUsageCertSign), true, false, fuzzHours, int64(-1))
	f.Add("Issuing", "www."+vtOther, vtDomain, vtDomain, vtDomain, false, true, false, true, int8(1), false, certSignCRL|uint16(x509.KeyUsageKeyEncipherment), false, true, int64(200*24), int64(1))
	f.Add("Issuing", "", "", vtDomain, vtDomain, true, false, true, false, int8(-1), true, uint16(x509.KeyUsageCertSign), false, false, int64(1), int64(0))
	// Each found by fuzzing against a weakened check: an unknown extended key
	// usage; constraints not critical.
	f.Add("0", "", vtDomain, vtDomain, vtDomain, true, true, true, true, int8(0), true, certSignCRL, false, true, fuzzHours, int64(-1))
	f.Add("0", "", vtDomain, vtDomain, vtDomain, false, true, true, true, int8(0), true, certSignCRL, false, false, fuzzHours, int64(-16))
	f.Fuzz(func(t *testing.T, cn, dnsName, dnsConstraints, uriConstraints, emailConstraints string,
		critical, isCA, excludeV4, excludeV6 bool, maxPathLen int8, maxPathLenZero bool, keyUsage uint16,
		clientAuth, unknownEKU bool, hours, startHours int64) {
		if hours <= 0 || hours > 24*365*30 || startHours < -24*365 || startHours > 24*365 {
			return
		}
		p := &fuzzIntermediate{
			cn: cn, dnsName: dnsName, dnsConstraints: dnsConstraints, uriConstraints: uriConstraints, emailConstraints: emailConstraints,
			critical: critical, isCA: isCA, excludeV4: excludeV4, excludeV6: excludeV6, maxPathLenZero: maxPathLenZero,
			clientAuth: clientAuth, unknownEKU: unknownEKU, maxPathLen: maxPathLen, keyUsage: keyUsage, hours: hours, startHours: startHours,
		}
		der, err := x509.CreateCertificate(rand.Reader, p.template(), root, issuingKey.Public(), rootKey)
		if err != nil {
			return // a template Go won't encode
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return
		}
		allowed := []string{vtDomain}
		now := vtNow.Add(time.Hour)
		if _, refused := ValidateIntermediate(cert, &ExpectedIntermediate{
			Roots: []*x509.Certificate{root}, PublicKey: issuingKey.Public(), AllowedDomains: allowed, Now: now,
		}); refused != nil {
			return
		}
		checkAcceptedShape(t, cert)
		checkAcceptedNameAndValidity(t, cert, root, now)
		checkAcceptedConstraints(t, cert, root, allowed)
		checkLeafOutsideRefused(t, cert, root, issuingKey, now)
	})
}

// FuzzValidConstraintDomain checks that what ValidConstraintDomain accepts is a
// lower-case DNS name of two LDH labels or more.
func FuzzValidConstraintDomain(f *testing.F) {
	for _, d := range []string{vtDomain, ldhDomain, underscoreDomain, "-a.internal", "a..internal", "com", "*.a.internal", "A.internal", "a.internal."} {
		f.Add(d)
	}
	f.Fuzz(func(t *testing.T, d string) {
		if ValidConstraintDomain(d) != nil {
			return
		}
		labels := strings.Split(d, ".")
		if len(labels) < 2 || len(d) > 253 {
			t.Fatalf("accepted %q", d)
		}
		for _, l := range labels {
			if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") || strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
				t.Fatalf("accepted %q (label %q)", d, l)
			}
		}
	})
}
