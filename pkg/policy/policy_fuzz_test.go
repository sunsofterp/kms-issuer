package policy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	csrBlock     = "CERTIFICATE REQUEST"
	evilName     = "evil.com"
	otherDomain  = "other.internal"
	upperDomain  = "eXAmple.internAl"
	systemMaster = "system:masters"
	day          = int64(24 * 3600)
	year         = int64(365 * 24)
)

// fuzzIssuer is the issuer the fuzz targets sign for, with or without wildcards.
func fuzzIssuer(wildcards bool) *Issuer {
	return &Issuer{PermittedDNSDomains: []string{testDomain, otherDomain}, AllowWildcards: wildcards, MaxDuration: 90 * 24 * time.Hour}
}

// within is the property the policy promises, stated independently of its code:
// name is a permitted domain or ends in "." and one, all lower case.
func within(name string, permitted []string) bool {
	for _, d := range permitted {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// hostnameRE is LDH labels of 1 to 63 characters, not starting or ending with a
// hyphen, lower case.
var hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// hostname reports whether h is a lower-case hostname of at most 253 characters.
func hostname(h string) bool {
	return len(h) <= 253 && hostnameRE.MatchString(h)
}

// checkIssued fails t unless an accepted template is a server certificate for
// permitted names only, valid from at most a few minutes back for exactly the
// requested duration, or less only to end with a CA that has an hour or more
// left, and never longer than the issuer's maximum or past the CA, as the
// package promises.
func checkIssued(t *testing.T, cert *x509.Certificate, iss *Issuer, ca *x509.Certificate, duration time.Duration) {
	t.Helper()
	checkShape(t, cert)
	checkNames(t, cert, iss)
	life := cert.NotAfter.Sub(cert.NotBefore)
	if cert.NotAfter.After(ca.NotAfter) || life > iss.MaxDuration || life > duration {
		t.Fatalf("validity %s to %s (asked %s, max %s, CA until %s)", cert.NotBefore, cert.NotAfter, duration, iss.MaxDuration, ca.NotAfter)
	}
	if now.Before(cert.NotBefore) || cert.NotBefore.Before(now.Add(-6*time.Minute)) {
		t.Fatalf("validity from %s, not from about now", cert.NotBefore)
	}
	if life < duration && (!cert.NotAfter.Equal(ca.NotAfter) || ca.NotAfter.Sub(now) < time.Hour) {
		t.Fatalf("validity cut to %s, not to a CA with an hour or more left (CA until %s)", cert.NotAfter, ca.NotAfter)
	}
}

// checkKey fails t unless the certificate's key is the request's.
func checkKey(t *testing.T, got, want crypto.PublicKey) {
	t.Helper()
	if k, ok := want.(interface{ Equal(crypto.PublicKey) bool }); !ok || !k.Equal(got) {
		t.Fatal("the certificate is not for the request's key")
	}
}

// checkShape: a server certificate, nothing more.
func checkShape(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	if cert.IsCA || !cert.BasicConstraintsValid {
		t.Fatalf("a CA or no basic constraints: %+v", cert)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(cert.UnknownExtKeyUsage) > 0 {
		t.Fatalf("extended key usage %v %v", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	if cert.KeyUsage&^(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) != 0 {
		t.Fatalf("key usage %b", cert.KeyUsage)
	}
	if len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses) > 0 || len(cert.ExtraExtensions) > 0 {
		t.Fatalf("names or extensions beyond DNS names: %+v", cert)
	}
}

// checkNames: permitted hostnames only, wildcards only if allowed, and a subject
// that is at most a common name among them.
func checkNames(t *testing.T, cert *x509.Certificate, iss *Issuer) {
	t.Helper()
	if len(cert.DNSNames) == 0 {
		t.Fatal("no DNS names")
	}
	for _, n := range cert.DNSNames {
		host, wildcard := strings.CutPrefix(n, "*.")
		if wildcard && !iss.AllowWildcards {
			t.Fatalf("wildcard %q without wildcards allowed", n)
		}
		if !hostname(host) || !within(host, iss.PermittedDNSDomains) {
			t.Fatalf("name %q is not a permitted hostname", n)
		}
	}
	cn := cert.Subject.CommonName
	if cn != "" && !slices.Contains(cert.DNSNames, cn) || len(cn) > 64 {
		t.Fatalf("common name %q not among %v, or too long", cn, cert.DNSNames)
	}
	if got := cert.Subject.String(); cn == "" && got != "" || cn != "" && got != "CN="+cn {
		t.Fatalf("subject %q holds more than the common name", got)
	}
}

// checkRequestAccepted fails t if an accepted request asked for a CA, an IP
// address or URI, a usage other than a server certificate's, or less than an hour.
func checkRequestAccepted(t *testing.T, isCA bool, tmpl *x509.CertificateRequest, usages []string, duration time.Duration) {
	t.Helper()
	switch {
	case isCA:
		t.Fatal("a CA request was accepted")
	case len(tmpl.IPAddresses)+len(tmpl.URIs) > 0:
		t.Fatal("a request with an IP address or URI was accepted")
	case duration < time.Hour:
		t.Fatalf("a request for %s was accepted", duration)
	}
	for _, u := range usages {
		if u != UsageServerAuth && u != UsageDigitalSignature && u != UsageKeyEncipherment {
			t.Fatalf("usage %q was accepted", u)
		}
	}
}

// fuzzCSR is a CSR for tmpl, or nil if Go won't encode it.
func fuzzCSR(key crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: csrBlock, Bytes: der})
}

// namesSeed is one input of FuzzTemplateNames.
type namesSeed struct {
	cn, names, ip, uri string
	wildcards, isCA    bool
	seconds            int64
	usages             string
	caHours            int64
}

// longName is a name in testDomain of exactly n characters (n of 18, or 20 or
// more), labels of up to 63.
func longName(n int) string {
	d := testDomain
	for len(d) < n {
		d = strings.Repeat("a", min(63, n-len(d)-1)) + "." + d
	}
	return d
}

// namesSeeds are a good request, then one for each rule of the policy that breaks
// only that rule (so dropping the rule lets the seed through), then other good
// ones, near each bound.
func namesSeeds() []namesSeed {
	good := namesSeed{cn: testName, names: testName, seconds: 30 * day, usages: UsageServerAuth, caHours: year}
	long := strings.Repeat("a", 48) + "." + testDomain // a 65-character name
	seeds := []namesSeed{good}
	for _, change := range []func(*namesSeed){
		func(s *namesSeed) { s.isCA = true },
		func(s *namesSeed) { s.ip = "10.0.0.1" },
		func(s *namesSeed) { s.uri = "https://x." + testDomain },
		func(s *namesSeed) { s.cn, s.names = "", "" },
		func(s *namesSeed) { s.cn, s.names = "", "*."+upperDomain },
		func(s *namesSeed) { s.cn, s.names, s.wildcards = "", "*.a_b."+testDomain, true },
		func(s *namesSeed) { s.cn, s.names = "", "a_b."+testDomain },
		func(s *namesSeed) { s.cn, s.names = "", testName+"." },
		func(s *namesSeed) { s.cn, s.names = "", upperDomain+" " },
		func(s *namesSeed) { s.cn, s.names = "", strings.Repeat("a", 64)+"."+testDomain },
		func(s *namesSeed) { s.cn, s.names = "", longName(254) },
		func(s *namesSeed) { s.cn, s.names = "", evilName },
		func(s *namesSeed) { s.cn, s.names = "", "bad"+testDomain },
		func(s *namesSeed) { s.cn, s.names = "", testDomain+".evil" },
		func(s *namesSeed) { s.cn = evilName },
		func(s *namesSeed) { s.cn = "0" },
		func(s *namesSeed) { s.cn, s.names = long, long },
		func(s *namesSeed) { s.usages = usageClientAut },
		func(s *namesSeed) { s.usages = UsageServerAuth + "," + usageClientAut },
		func(s *namesSeed) { s.seconds = 59 * 60 },
		func(s *namesSeed) { s.seconds = 91 * day },
		func(s *namesSeed) { s.caHours = 0 },
		// Good too.
		func(s *namesSeed) {
			s.cn, s.names, s.usages = mixedCaseName, "SSO-Admin.Example.Internal,x."+otherDomain+","+testDomain, UsageDigitalSignature+","+UsageKeyEncipherment
		},
		func(s *namesSeed) {
			s.cn, s.names, s.wildcards, s.seconds = "", testWildcard+","+upperDomain, true, 3600
		},
		func(s *namesSeed) { s.cn, s.names, s.seconds = "", strings.Repeat("a", 63)+"."+testDomain, 0 },
		func(s *namesSeed) { s.cn, s.names = "", longName(253) },
		func(s *namesSeed) { s.cn, s.names = long[1:], long[1:]+","+testName },
		func(s *namesSeed) { s.seconds, s.caHours = 90*day, 10*24 },
		func(s *namesSeed) { s.caHours = 2 },
	} {
		s := good
		change(&s)
		seeds = append(seeds, s)
	}
	return seeds
}

// FuzzTemplateNames signs CSRs whose names, common name, extra SANs, usages and
// duration come from the fuzzer, under a CA whose remaining life does too, and
// checks every accepted one.
func FuzzTemplateNames(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range namesSeeds() {
		f.Add(s.cn, s.names, s.ip, s.uri, s.wildcards, s.isCA, s.seconds, s.usages, s.caHours)
	}
	f.Fuzz(func(t *testing.T, cn, names, ip, uri string, wildcards, isCA bool, seconds int64, usages string, caHours int64) {
		if caHours < 0 || caHours > 20*year {
			return
		}
		tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
		if names != "" {
			tmpl.DNSNames = strings.Split(names, ",")
		}
		if parsed := net.ParseIP(ip); parsed != nil {
			tmpl.IPAddresses = []net.IP{parsed}
		}
		if u, err := url.Parse(uri); err == nil && uri != "" {
			tmpl.URIs = []*url.URL{u}
		}
		csr := fuzzCSR(key, tmpl)
		if csr == nil {
			return
		}
		iss := fuzzIssuer(wildcards)
		ca := &x509.Certificate{IsCA: true, NotAfter: now.Add(time.Duration(caHours) * time.Hour)}
		req := &Request{CSR: csr, IsCA: isCA, Usages: strings.Split(usages, ","), Duration: time.Duration(seconds) * time.Second, DefaultDuration: time.Hour}
		cert, pub, err := Template(req, iss, ca, serial, now)
		if err != nil {
			return
		}
		duration := req.Duration
		if duration == 0 {
			duration = req.DefaultDuration
		}
		checkRequestAccepted(t, isCA, tmpl, req.Usages, duration)
		checkIssued(t, cert, iss, ca, duration)
		checkKey(t, pub, key.Public())
	})
}

// The request keys FuzzTemplateCSR chooses from: the first four acceptable, the
// rest not.
const (
	keyP256 = iota
	keyP384
	keyEd25519
	keyRSA2048
	keyP224
	keyRSA1024
	keyKinds
)

func fuzzKeys(f *testing.F) []crypto.Signer {
	keys := make([]crypto.Signer, keyKinds)
	for kind, curve := range map[int]elliptic.Curve{keyP256: elliptic.P256(), keyP384: elliptic.P384(), keyP224: elliptic.P224()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			f.Fatal(err)
		}
		keys[kind] = k
	}
	for kind, bits := range map[int]int{keyRSA2048: 2048, keyRSA1024: 1024} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			f.Fatal(err)
		}
		keys[kind] = k
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	keys[keyEd25519] = ed
	return keys
}

// sanOf is a subjectAltName extension's value holding names.
func sanOf(f *testing.F, names ...asn1.RawValue) []byte {
	der, err := asn1.Marshal(names)
	if err != nil {
		f.Fatal(err)
	}
	return der
}

// subjectOf is a DER subject.
func subjectOf(f *testing.F, name *pkix.Name) []byte {
	der, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		f.Fatal(err)
	}
	return der
}

// sanName is a subjectAltName entry of a context-specific tag.
func sanName(tag int, value string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: []byte(value)}
}

// csrSeed is one input of FuzzTemplateCSR.
type csrSeed struct {
	subject, san []byte
	key          uint8
	trailing     []byte
	tamper       bool
}

// csrSeeds are a good request, then one for each rule of the policy's request
// checks that breaks only that rule, then other good ones.
func csrSeeds(f *testing.F) []csrSeed {
	dns := sanName(2, testName)
	good := csrSeed{subject: subjectOf(f, &pkix.Name{CommonName: testName}), san: sanOf(f, dns), key: keyP256}
	seeds := []csrSeed{good}
	for _, change := range []func(*csrSeed){
		func(s *csrSeed) {
			s.san = sanOf(f, dns, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{0x06, 0x01, 0x2a}})
		},
		func(s *csrSeed) {
			s.san = sanOf(f, dns, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: s.subject})
		},
		func(s *csrSeed) { s.san = sanOf(f, dns, sanName(1, "a@"+testDomain)) },
		func(s *csrSeed) { s.san = sanOf(f, dns, sanName(6, "https://x."+testDomain)) },
		func(s *csrSeed) { s.san = sanOf(f, dns, sanName(7, "\x0a\x00\x00\x01")) },
		func(s *csrSeed) { s.san = append(sanOf(f, dns), 0) },
		func(s *csrSeed) { s.subject, s.san = nil, nil },
		func(s *csrSeed) { s.subject = subjectOf(f, &pkix.Name{CommonName: evilName}) },
		func(s *csrSeed) { s.key = keyP224 },
		func(s *csrSeed) { s.key = keyRSA1024 },
		func(s *csrSeed) { s.trailing = []byte("junk") },
		func(s *csrSeed) { s.tamper = true },
		// Good too.
		func(s *csrSeed) { s.key = keyRSA2048 },
		func(s *csrSeed) { s.key = keyP384 },
		func(s *csrSeed) { s.key, s.subject = keyEd25519, nil },
		func(s *csrSeed) {
			s.subject = subjectOf(f, &pkix.Name{CommonName: testName, Organization: []string{systemMaster}})
			s.san, s.trailing = sanOf(f, dns, sanName(2, "x."+otherDomain)), []byte("\n\t\n")
		},
	} {
		s := good
		change(&s)
		seeds = append(seeds, s)
	}
	return seeds
}

// dnsNamesOnly reports whether san is a subjectAltName value of DNS names only,
// read with encoding/asn1 rather than the policy's parser.
func dnsNamesOnly(san []byte) bool {
	var names []asn1.RawValue
	if rest, err := asn1.Unmarshal(san, &names); err != nil || len(rest) > 0 {
		return false
	}
	for _, n := range names {
		if n.Class != asn1.ClassContextSpecific || n.Tag != 2 || n.IsCompound {
			return false
		}
	}
	return true
}

// FuzzTemplateCSR signs requests whose subject and subjectAltName bytes, key and
// trailing data come from the fuzzer, signed validly (or not, when tampered with)
// so that the fuzzed structure reaches the policy's checks, and checks every
// accepted one: DNS names only, an acceptable key, nothing after the request, a
// valid signature, and the same certificate checks as FuzzTemplateNames.
func FuzzTemplateCSR(f *testing.F) {
	keys := fuzzKeys(f)
	for _, s := range csrSeeds(f) {
		f.Add(s.subject, s.san, s.key, s.trailing, s.tamper)
	}
	f.Fuzz(func(t *testing.T, subject, san []byte, key uint8, trailing []byte, tamper bool) {
		kind := key % keyKinds
		tmpl := &x509.CertificateRequest{RawSubject: subject}
		if san != nil {
			tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAltName, Value: san}}
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, keys[kind])
		if err != nil {
			return
		}
		if tamper {
			der[len(der)-1] ^= 0xff
		}
		data := append(pem.EncodeToMemory(&pem.Block{Type: csrBlock, Bytes: der}), trailing...)
		iss := fuzzIssuer(false)
		cert, pub, err := Template(&Request{CSR: data, DefaultDuration: 24 * time.Hour}, iss, parent, serial, now)
		if err != nil {
			return
		}
		switch {
		case tamper:
			t.Fatal("a request with a broken signature was accepted")
		case strings.TrimSpace(string(trailing)) != "":
			t.Fatalf("a request followed by %q was accepted", trailing)
		case kind >= keyP224:
			t.Fatalf("a request for key kind %d was accepted", kind)
		case !dnsNamesOnly(san):
			t.Fatalf("a request with subjectAltName %x was accepted", san)
		}
		checkIssued(t, cert, iss, parent, 24*time.Hour)
		checkKey(t, pub, keys[kind].Public())
	})
}
