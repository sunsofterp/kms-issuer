package kmsca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	vtDomain    = "example.internal"
	vtSubDomain = "sub.example.internal"
	vtOther     = "other.internal"
	vtDays      = 24 * time.Hour
)

var vtNow = time.Date(2026, time.November, 25, 12, 0, 0, 0, time.UTC)

func vtKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// vtRoot self-signs a root for the domains with key.
func vtRoot(t *testing.T, key *ecdsa.PrivateKey, name string, domains ...string) *x509.Certificate {
	t.Helper()
	tmpl, err := CATemplate(&CAInput{Subject: pkix.Name{CommonName: name}, PermittedDNSDomains: domains, Duration: 365 * vtDays, Now: vtNow}, Root)
	if err != nil {
		t.Fatal(err)
	}
	return vtSign(t, tmpl, tmpl, key.Public(), key)
}

// vtIntermediate signs a 90-day intermediate for pub under root (with rootKey),
// after mutate.
func vtIntermediate(t *testing.T, root *x509.Certificate, rootKey crypto.Signer, pub crypto.PublicKey, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	tmpl, err := CATemplate(&CAInput{Subject: pkix.Name{CommonName: "Issuing"}, PermittedDNSDomains: []string{vtDomain}, Duration: 90 * vtDays, Now: vtNow}, Intermediate)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(tmpl)
	}
	return vtSign(t, tmpl, root, pub, rootKey)
}

func vtSign(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Each refusal of ValidateIntermediate's explicit checks, and each condition of
// each, by its own check (the error names it), so that dropping any one fails here
// even where a later one would also refuse. What only the final Verify refuses is
// TestValidateIntermediateVerifyOnly.
func TestValidateIntermediateRefusals(t *testing.T) {
	const (
		wantRootKey        = "the issuing key is a root key"
		wantEKU            = "extended key usage is not exactly server auth"
		wantURIEmail       = "URI and email names are not limited"
		wantIPs            = "IP addresses are not all excluded"
		wantOutsideAllowed = "outside the allowed domains"
		wantRootName       = "the intermediate's name is the root's"
	)
	rootKey, issuingKey, otherKey := vtKey(t), vtKey(t), vtKey(t)
	root := vtRoot(t, rootKey, "Root", vtDomain)
	expect := func(change func(*ExpectedIntermediate)) *ExpectedIntermediate {
		e := &ExpectedIntermediate{Roots: []*x509.Certificate{root}, PublicKey: issuingKey.Public(), AllowedDomains: []string{vtDomain}, Now: vtNow.Add(time.Hour)}
		if change != nil {
			change(e)
		}
		return e
	}
	good := vtIntermediate(t, root, rootKey, issuingKey.Public(), nil)
	if got, err := ValidateIntermediate(good, expect(nil)); err != nil || !got.Equal(root) {
		t.Fatalf("a good intermediate: root %v, %v", got != nil, err)
	}

	// A root on another key with the same name: its intermediate claims the pinned
	// root as issuer but is not signed by it.
	impostor := vtRoot(t, otherKey, "Root", vtDomain)
	// A pinned root not valid now, whose key is the intermediate's.
	otherRoot := vtRoot(t, issuingKey, "Other Root", vtDomain)

	for _, c := range []struct {
		name   string
		cert   *x509.Certificate
		expect *ExpectedIntermediate
		want   string
	}{
		{"no intermediate", nil, expect(nil), "no intermediate certificate"},
		{"no pinned root", good, expect(func(e *ExpectedIntermediate) { e.Roots = nil }), "no root certificate"},
		{"another key", good, expect(func(e *ExpectedIntermediate) { e.PublicKey = otherKey.Public() }), "not for the issuer's KMS key"},
		{"a pinned root's key", vtIntermediate(t, root, rootKey, rootKey.Public(), nil),
			expect(func(e *ExpectedIntermediate) { e.PublicKey = rootKey.Public() }), wantRootKey},
		{"another pinned root's key", good, expect(func(e *ExpectedIntermediate) { e.OtherRoots = []*x509.Certificate{otherRoot} }),
			wantRootKey},
		{"not signed by the pinned root", vtIntermediate(t, impostor, otherKey, issuingKey.Public(), nil), expect(nil), "not issued by a pinned root"},
		{"the root's name", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) { c.Subject = root.Subject }),
			expect(nil), wantRootName},
		{"not a CA", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.IsCA, c.MaxPathLen, c.MaxPathLenZero = false, -1, false
		}), expect(nil), "not a CA certificate"},
		{"path length 1", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 1, false }),
			expect(nil), "path length is not 0"},
		{"no cert-sign", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCRLSign }),
			expect(nil), "no cert-sign key usage"},
		{"key encipherment too", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment }),
			expect(nil), "unexpected key usages"},
		{"client auth too", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		}), expect(nil), wantEKU},
		{"an unknown usage too", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}), expect(nil), wantEKU},
		{"the root's common name in another name", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.Subject = pkix.Name{CommonName: root.Subject.CommonName, Organization: []string{"Other"}}
		}), expect(nil), wantRootName},
		{"constraints not critical", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false }),
			expect(nil), "name constraints are missing or not critical"},
		{"no DNS constraint", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) { c.PermittedDNSDomains = nil }),
			expect(nil), "no permitted DNS domain"},
		{"URIs not limited", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) { c.PermittedURIDomains = nil }),
			expect(nil), wantURIEmail},
		{"emails not limited", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) { c.PermittedEmailAddresses = nil }),
			expect(nil), wantURIEmail},
		{"an IP family not excluded", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) { c.ExcludedIPRanges = c.ExcludedIPRanges[:1] }),
			expect(nil), wantIPs},
		{"an IP range permitted", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.PermittedIPRanges = []*net.IPNet{{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}}
		}), expect(nil), wantIPs},
		{"a URI constraint outside the allowed domains", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.PermittedURIDomains = []string{vtOther}
		}), expect(nil), wantOutsideAllowed},
		{"an email constraint outside the allowed domains", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.PermittedEmailAddresses = []string{vtOther}
		}), expect(nil), wantOutsideAllowed},
		{"longer than the operator's maximum", good, expect(func(e *ExpectedIntermediate) { e.MaxDuration = 30 * vtDays }), "longer than the 720h0m0s"},
		{"longer than the package maximum", vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.NotAfter = c.NotBefore.Add(MaxIntermediateDuration + time.Second)
		}), expect(nil), "longer than the 4392h0m0s"},
		{"allowed domains elsewhere", good, expect(func(e *ExpectedIntermediate) { e.AllowedDomains = []string{vtOther} }), wantOutsideAllowed},
		{"expired", good, expect(func(e *ExpectedIntermediate) { e.Now = good.NotAfter.Add(time.Minute) }), "expired at"},
		{"before its notBefore", good, expect(func(e *ExpectedIntermediate) { e.Now = good.NotBefore.Add(-time.Minute) }), "not valid yet"},
	} {
		_, err := ValidateIntermediate(c.cert, c.expect)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// What only the final Verify (path validation as clients do it) refuses: each
// passes every explicit check before it.
func TestValidateIntermediateVerifyOnly(t *testing.T) {
	rootKey, issuingKey := vtKey(t), vtKey(t)
	critical := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{0x05, 0x00}}
	// rootWith self-signs a root after change.
	rootWith := func(d time.Duration, change func(*x509.Certificate)) *x509.Certificate {
		tmpl, err := CATemplate(&CAInput{Subject: pkix.Name{CommonName: "Root"}, PermittedDNSDomains: []string{vtDomain}, Duration: d, Now: vtNow}, Root)
		if err != nil {
			t.Fatal(err)
		}
		if change != nil {
			change(tmpl)
		}
		return vtSign(t, tmpl, tmpl, rootKey.Public(), rootKey)
	}
	root := rootWith(365*vtDays, nil)
	clientAuthRoot := rootWith(365*vtDays, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} })
	criticalRoot := rootWith(365*vtDays, func(c *x509.Certificate) { c.ExtraExtensions = []pkix.Extension{critical} })
	shortRoot := rootWith(30*vtDays, nil)

	for _, c := range []struct {
		name string
		root *x509.Certificate
		cert *x509.Certificate
		now  time.Time
	}{
		{"an unknown critical extension", root, vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{critical}
		}), vtNow.Add(time.Hour)},
		{"a DNS name outside the root's constraints", root, vtIntermediate(t, root, rootKey, issuingKey.Public(), func(c *x509.Certificate) {
			c.DNSNames = []string{"www." + vtOther}
		}), vtNow.Add(time.Hour)},
		{"a root for client auth only", clientAuthRoot, vtIntermediate(t, clientAuthRoot, rootKey, issuingKey.Public(), nil), vtNow.Add(time.Hour)},
		{"a root with an unknown critical extension", criticalRoot, vtIntermediate(t, criticalRoot, rootKey, issuingKey.Public(), nil), vtNow.Add(time.Hour)},
		// The intermediate outlives its root: valid itself, under a root expired.
		{"an expired root", shortRoot, vtIntermediate(t, shortRoot, rootKey, issuingKey.Public(), nil), vtNow.Add(40 * vtDays)},
	} {
		_, err := ValidateIntermediate(c.cert, &ExpectedIntermediate{
			Roots: []*x509.Certificate{c.root}, PublicKey: issuingKey.Public(), AllowedDomains: []string{vtDomain}, Now: c.now,
		})
		if err == nil || !strings.Contains(err.Error(), "does not verify to the pinned root") {
			t.Errorf("%s: %v, want refused by path validation", c.name, err)
		}
	}
}

// An intermediate's constraints must be inside the root's even when the allowed
// domains are wider.
func TestValidateIntermediateWithinTheRoot(t *testing.T) {
	rootKey, issuingKey := vtKey(t), vtKey(t)
	narrow := vtRoot(t, rootKey, "Root", vtSubDomain)
	cert := vtIntermediate(t, narrow, rootKey, issuingKey.Public(), nil) // permits example.internal
	_, err := ValidateIntermediate(cert, &ExpectedIntermediate{
		Roots: []*x509.Certificate{narrow}, PublicKey: issuingKey.Public(), AllowedDomains: []string{vtDomain}, Now: vtNow.Add(time.Hour),
	})
	if err == nil || !strings.Contains(err.Error(), "outside the root's") {
		t.Errorf("constraints wider than the root's: %v, want refused as outside the root's", err)
	}
}

// Each malformed label is refused by the label check itself.
func TestValidConstraintDomainLabels(t *testing.T) {
	for _, d := range []string{
		"ex_ample.internal",
		"-example.internal",
		"example-.internal",
		"example..internal",
		strings.Repeat("a", 64) + ".internal",
	} {
		if err := ValidConstraintDomain(d); err == nil || !strings.Contains(err.Error(), "invalid label") {
			t.Errorf("%q: %v, want an invalid label", d, err)
		}
	}
	for _, d := range []string{"a-b.internal", strings.Repeat("a", 63) + ".internal", "x1.internal"} {
		if err := ValidConstraintDomain(d); err != nil {
			t.Errorf("%q refused: %v", d, err)
		}
	}
}
