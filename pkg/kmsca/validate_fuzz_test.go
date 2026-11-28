package kmsca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	ldhDomain        = "a-b.internal"
	underscoreDomain = "ex_ample.internal"
	fuzzHours        = int64(90 * 24)
	certSignCRL      = uint16(x509.KeyUsageCertSign | x509.KeyUsageCRLSign)
)

// Which key an intermediate is for, and who signs it.
const (
	keyIssuing   = iota // the issuer's key, signed by the pinned root
	keyRoot             // the pinned root's own key
	keyOther            // a key that isn't the issuer's
	keyImpostor         // the issuer's key, signed by another key under the root's name
	keyOtherRoot        // the issuer's key, which is also another pinned root's
	keyChoices
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
	cn, dnsName, dnsConstraints, uriConstraints, emailConstraints  string
	critical, isCA, excludeV4, excludeV6, permitIP, maxPathLenZero bool
	clientAuth, unknownEKU                                         bool
	maxPathLen                                                     int8
	keyUsage                                                       uint16
	hours, startHours                                              int64
	key                                                            uint8
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
	if p.permitIP {
		tmpl.PermittedIPRanges = []*net.IPNet{{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}}
	}
	if p.clientAuth {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if p.unknownEKU {
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
	}
	return tmpl
}

// fuzzRoot self-signs a root for both test domains that excludes no IP address:
// wider than the one domain the fuzz targets allow, so that only the intermediate
// stands between a leaf outside the allowed domain and verification.
func fuzzRoot(t testing.TB, key *ecdsa.PrivateKey, name string) *x509.Certificate {
	t.Helper()
	tmpl, err := CATemplate(&CAInput{Subject: pkix.Name{CommonName: name}, PermittedDNSDomains: []string{vtDomain, vtOther}, Duration: 365 * vtDays, Now: vtNow}, Root)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.ExcludedIPRanges = nil
	return vtSign(t, tmpl, tmpl, key.Public(), key)
}

// fuzzHarness holds the keys and roots the intermediates are made with.
type fuzzHarness struct {
	rootKey, issuingKey, otherKey *ecdsa.PrivateKey
	// root is the pinned root; impostor has its name on another key; otherRoot is
	// another pinned root, on the issuing key.
	root, impostor, otherRoot *x509.Certificate
}

func newFuzzHarness(t testing.TB) *fuzzHarness {
	h := &fuzzHarness{rootKey: vtKey(t), issuingKey: vtKey(t), otherKey: vtKey(t)}
	h.root = fuzzRoot(t, h.rootKey, vtRootName)
	h.impostor = fuzzRoot(t, h.otherKey, vtRootName)
	h.otherRoot = fuzzRoot(t, h.issuingKey, "Other Root")
	return h
}

// sign makes p's intermediate as its key choice says, and returns it with what
// ValidateIntermediate is to expect of it, or nil if Go won't encode it.
func (h *fuzzHarness) sign(p *fuzzIntermediate, now time.Time) (*x509.Certificate, *ExpectedIntermediate) {
	pub, parent, signer := h.issuingKey.Public(), h.root, crypto.Signer(h.rootKey)
	expected := &ExpectedIntermediate{Roots: []*x509.Certificate{h.root}, PublicKey: h.issuingKey.Public(), AllowedDomains: []string{vtDomain}, Now: now}
	switch p.key % keyChoices {
	case keyRoot:
		pub = h.rootKey.Public()
		expected.PublicKey = pub
	case keyOther:
		pub = h.otherKey.Public()
	case keyImpostor:
		parent, signer = h.impostor, h.otherKey
	case keyOtherRoot:
		expected.OtherRoots = []*x509.Certificate{h.otherRoot}
	}
	der, err := x509.CreateCertificate(rand.Reader, p.template(), parent, pub, signer)
	if err != nil {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil
	}
	return cert, expected
}

// sameKey reports whether a and b are the same ECDSA public key.
func sameKey(a, b crypto.PublicKey) bool {
	ka, ok := a.(*ecdsa.PublicKey)
	return ok && ka.Equal(b)
}

// checkAcceptedKey fails t unless cert is for the issuer's key, which is no
// pinned root's, and was issued and signed by the pinned root.
func checkAcceptedKey(t *testing.T, cert *x509.Certificate, h *fuzzHarness, expected *ExpectedIntermediate) {
	t.Helper()
	switch {
	case !sameKey(cert.PublicKey, expected.PublicKey):
		t.Fatal("accepted: not for the issuer's key")
	case sameKey(cert.PublicKey, h.root.PublicKey) || len(expected.OtherRoots) > 0 && sameKey(cert.PublicKey, h.otherRoot.PublicKey):
		t.Fatal("accepted: for a root's key")
	case !bytes.Equal(cert.RawIssuer, h.root.RawSubject) || cert.CheckSignatureFrom(h.root) != nil:
		t.Fatal("accepted: not issued and signed by the pinned root")
	}
}

// excludesRange reports whether ranges holds cidr exactly.
func excludesRange(ranges []*net.IPNet, cidr string) bool {
	for _, r := range ranges {
		if r.String() == cidr {
			return true
		}
	}
	return false
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
	}
}

// checkAcceptedIPs fails t unless cert permits no IP range and excludes them all.
func checkAcceptedIPs(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	if len(cert.PermittedIPRanges) > 0 || !excludesRange(cert.ExcludedIPRanges, "0.0.0.0/0") || !excludesRange(cert.ExcludedIPRanges, "::/0") {
		t.Fatal("accepted: IP addresses not all excluded")
	}
}

// checkAcceptedNameAndValidity fails t unless cert has a name, not the root's, and
// is valid now and no longer-lived than allowed.
func checkAcceptedNameAndValidity(t *testing.T, cert, root *x509.Certificate, now time.Time) {
	t.Helper()
	if cert.Subject.String() == "" || cert.Subject.CommonName == root.Subject.CommonName {
		t.Fatalf("accepted: the name %q", cert.Subject)
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.NotAfter.Sub(cert.NotBefore) > MaxIntermediateDuration {
		t.Fatal("accepted: not valid now, or too long")
	}
}

// inside reports whether the host a name constraint names (an email constraint's
// after its "@", a URI constraint's without its leading ".") is one of ds or
// under one, ignoring case and a trailing dot.
func inside(c string, ds []string) bool {
	if at := strings.LastIndexByte(c, '@'); at >= 0 {
		c = c[at+1:]
	}
	c = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(c, "."), "."))
	for _, d := range ds {
		if c != "" && (c == d || strings.HasSuffix(c, "."+d)) {
			return true
		}
	}
	return false
}

// checkAcceptedConstraints fails t unless every constraint of cert is inside the
// allowed domains and the root's.
func checkAcceptedConstraints(t *testing.T, cert, root *x509.Certificate, allowed []string) {
	t.Helper()
	for _, list := range [][]string{cert.PermittedDNSDomains, cert.PermittedURIDomains, cert.PermittedEmailAddresses} {
		for _, c := range list {
			if !inside(c, allowed) || !inside(c, root.PermittedDNSDomains) {
				t.Fatalf("accepted: constraint %q outside the allowed domains", c)
			}
		}
	}
}

// outsideLeaves are leaf templates for names outside the allowed domain, one per
// name type: a client must refuse each under an accepted intermediate.
func outsideLeaves() map[string]*x509.Certificate {
	uri, _ := url.Parse("https://x." + vtOther + "/")
	return map[string]*x509.Certificate{
		"DNS name":      {DNSNames: []string{"x." + vtOther}},
		"IPv4 address":  {IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)}},
		"IPv6 address":  {IPAddresses: []net.IP{net.ParseIP("fd00::1")}},
		"URI":           {URIs: []*url.URL{uri}},
		"email address": {EmailAddresses: []string{"a@" + vtOther}},
	}
}

// verifyLeaf signs leaf under cert with issuingKey and verifies it to root, as a
// client does.
func verifyLeaf(t testing.TB, leaf, cert, root *x509.Certificate, issuingKey crypto.Signer, now time.Time) error {
	t.Helper()
	leaf.SerialNumber, leaf.NotBefore, leaf.NotAfter = big.NewInt(3), now.Add(-time.Minute), now.Add(time.Hour)
	leaf.KeyUsage, leaf.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	leafCert := vtSign(t, leaf, cert, vtKey(t).Public(), issuingKey)
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(cert)
	_, err := leafCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: now})
	return err
}

// checkLeavesOutsideRefused fails t unless every outside leaf signed under cert
// is refused for its name. The root permits them all, so only cert can refuse.
func checkLeavesOutsideRefused(t *testing.T, cert, root *x509.Certificate, issuingKey crypto.Signer, now time.Time) {
	t.Helper()
	for kind, leaf := range outsideLeaves() {
		var invalid x509.CertificateInvalidError
		if err := verifyLeaf(t, leaf, cert, root, issuingKey, now); !errors.As(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
			t.Fatalf("accepted an intermediate under which a leaf for a %s outside the allowed domains is not refused for its name: %v", kind, err)
		}
	}
}

// The leaf check has teeth: under the fuzz root, an intermediate with no name
// constraints lets every outside leaf verify, and a leaf inside verifies under the
// intermediate kms-ca makes.
func TestFuzzLeafCheckHasTeeth(t *testing.T) {
	h := newFuzzHarness(t)
	now := vtNow.Add(time.Hour)
	unconstrained := vtIntermediate(t, h.root, h.rootKey, h.issuingKey.Public(), func(c *x509.Certificate) {
		c.PermittedDNSDomainsCritical = false
		c.PermittedDNSDomains, c.PermittedURIDomains, c.PermittedEmailAddresses, c.ExcludedIPRanges = nil, nil, nil, nil
	})
	for kind, leaf := range outsideLeaves() {
		if err := verifyLeaf(t, leaf, unconstrained, h.root, h.issuingKey, now); err != nil {
			t.Errorf("a %s under an unconstrained intermediate: %v, want it verified", kind, err)
		}
	}
	good := vtIntermediate(t, h.root, h.rootKey, h.issuingKey.Public(), nil)
	if err := verifyLeaf(t, &x509.Certificate{DNSNames: []string{"x." + vtDomain}}, good, h.root, h.issuingKey, now); err != nil {
		t.Errorf("a leaf inside under a good intermediate: %v", err)
	}
}

// intermediateSeeds are a good intermediate, then one for each rule of
// ValidateIntermediate that breaks only that rule (so dropping the rule lets the
// seed through), then other good ones.
func intermediateSeeds() []fuzzIntermediate {
	good := fuzzIntermediate{
		cn: vtIssuing, dnsConstraints: vtDomain, uriConstraints: vtDomain, emailConstraints: vtDomain,
		critical: true, isCA: true, excludeV4: true, excludeV6: true, maxPathLenZero: true,
		keyUsage: certSignCRL, hours: fuzzHours, startHours: -1,
	}
	seeds := []fuzzIntermediate{good}
	for _, change := range []func(*fuzzIntermediate){
		func(p *fuzzIntermediate) { p.cn = "" },
		func(p *fuzzIntermediate) { p.cn = vtRootName },
		// Go won't encode a path length on a non-CA, so this also breaks the
		// path-length rule.
		func(p *fuzzIntermediate) { p.isCA, p.maxPathLen, p.maxPathLenZero = false, -1, false },
		func(p *fuzzIntermediate) { p.maxPathLen, p.maxPathLenZero = 1, false },
		func(p *fuzzIntermediate) { p.keyUsage = uint16(x509.KeyUsageCRLSign) },
		func(p *fuzzIntermediate) { p.keyUsage |= uint16(x509.KeyUsageKeyEncipherment) },
		func(p *fuzzIntermediate) { p.clientAuth = true },
		func(p *fuzzIntermediate) { p.unknownEKU = true },
		func(p *fuzzIntermediate) { p.hours = int64(MaxIntermediateDuration/time.Hour) + 1 },
		func(p *fuzzIntermediate) { p.critical = false },
		func(p *fuzzIntermediate) { p.dnsConstraints = "" },
		func(p *fuzzIntermediate) { p.uriConstraints = "" },
		func(p *fuzzIntermediate) { p.emailConstraints = "" },
		func(p *fuzzIntermediate) { p.excludeV4 = false },
		func(p *fuzzIntermediate) { p.excludeV6 = false },
		func(p *fuzzIntermediate) { p.permitIP = true },
		func(p *fuzzIntermediate) { p.dnsConstraints = vtDomain + "," + vtOther },
		func(p *fuzzIntermediate) { p.uriConstraints = vtOther },
		func(p *fuzzIntermediate) { p.emailConstraints = vtOther },
		func(p *fuzzIntermediate) { p.uriConstraints = "bad" + vtDomain },
		func(p *fuzzIntermediate) { p.startHours = 2 },
		func(p *fuzzIntermediate) { p.startHours, p.hours = -48, 24 },
		func(p *fuzzIntermediate) { p.key = keyRoot },
		func(p *fuzzIntermediate) { p.key = keyOther },
		func(p *fuzzIntermediate) { p.key = keyImpostor },
		func(p *fuzzIntermediate) { p.key = keyOtherRoot },
		// Good too.
		func(p *fuzzIntermediate) {
			p.dnsConstraints, p.uriConstraints, p.emailConstraints = vtSubDomain, "."+vtSubDomain, vtDomain
			p.keyUsage |= uint16(x509.KeyUsageDigitalSignature)
		},
		func(p *fuzzIntermediate) {
			p.keyUsage, p.dnsName, p.hours = uint16(x509.KeyUsageCertSign), "www."+vtOther, 30*24
		},
	} {
		p := good
		change(&p)
		seeds = append(seeds, p)
	}
	return seeds
}

// FuzzValidateIntermediate signs intermediates whose key, signer, names,
// constraints, usages, path length and validity come from the fuzzer, and checks
// that whatever ValidateIntermediate accepts is what its contract promises: in
// particular, an intermediate under which a client refuses every leaf outside the
// allowed domain, under a root that would accept them.
func FuzzValidateIntermediate(f *testing.F) {
	h := newFuzzHarness(f)
	for _, p := range intermediateSeeds() {
		f.Add(p.cn, p.dnsName, p.dnsConstraints, p.uriConstraints, p.emailConstraints,
			p.critical, p.isCA, p.excludeV4, p.excludeV6, p.permitIP, p.maxPathLen, p.maxPathLenZero, p.keyUsage,
			p.clientAuth, p.unknownEKU, p.hours, p.startHours, p.key)
	}
	f.Fuzz(func(t *testing.T, cn, dnsName, dnsConstraints, uriConstraints, emailConstraints string,
		critical, isCA, excludeV4, excludeV6, permitIP bool, maxPathLen int8, maxPathLenZero bool, keyUsage uint16,
		clientAuth, unknownEKU bool, hours, startHours int64, key uint8) {
		if hours <= 0 || hours > 24*365*30 || startHours < -24*365 || startHours > 24*365 {
			return
		}
		p := &fuzzIntermediate{
			cn: cn, dnsName: dnsName, dnsConstraints: dnsConstraints, uriConstraints: uriConstraints, emailConstraints: emailConstraints,
			critical: critical, isCA: isCA, excludeV4: excludeV4, excludeV6: excludeV6, permitIP: permitIP, maxPathLenZero: maxPathLenZero,
			clientAuth: clientAuth, unknownEKU: unknownEKU, maxPathLen: maxPathLen, keyUsage: keyUsage, hours: hours, startHours: startHours, key: key,
		}
		now := vtNow.Add(time.Hour)
		cert, expected := h.sign(p, now)
		if cert == nil {
			return // a template Go won't encode
		}
		root, refused := ValidateIntermediate(cert, expected)
		if refused != nil {
			return
		}
		if !root.Equal(h.root) {
			t.Fatal("accepted under a root other than the pinned one")
		}
		checkAcceptedKey(t, cert, h, expected)
		checkAcceptedShape(t, cert)
		checkAcceptedIPs(t, cert)
		checkAcceptedNameAndValidity(t, cert, h.root, now)
		checkAcceptedConstraints(t, cert, h.root, expected.AllowedDomains)
		checkLeavesOutsideRefused(t, cert, h.root, h.issuingKey, now)
	})
}

// dnsDomain is a lower-case DNS name of two LDH labels or more, each of 1 to 63
// characters not starting or ending with a hyphen.
var dnsDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// FuzzValidConstraintDomain checks that what ValidConstraintDomain accepts is a
// lower-case DNS name of two LDH labels or more, at most 253 characters.
func FuzzValidConstraintDomain(f *testing.F) {
	for _, d := range []string{
		vtDomain, ldhDomain, underscoreDomain, "-a.internal", "a..internal", "com", "*.a.internal", "A.internal", "a.internal.",
		strings.Repeat("a", 63) + ".internal", strings.Repeat("a", 64) + ".internal", longDomain(253), longDomain(254),
	} {
		f.Add(d)
	}
	f.Fuzz(func(t *testing.T, d string) {
		if ValidConstraintDomain(d) != nil {
			return
		}
		if len(d) > 253 || !dnsDomain.MatchString(d) {
			t.Fatalf("accepted %q", d)
		}
	})
}
