package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
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

// hostname reports whether h is LDH labels of 1-63 characters, no leading or
// trailing hyphen, at most 253 characters.
func hostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		if strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return true
}

// checkIssued fails t unless an accepted template is a server certificate for
// permitted names only, within the requested duration, the issuer's maximum and
// the CA's own validity, as the package promises.
func checkIssued(t *testing.T, cert *x509.Certificate, iss *Issuer, ca *x509.Certificate, duration time.Duration) {
	t.Helper()
	checkShape(t, cert)
	checkNames(t, cert, iss)
	if cert.NotAfter.After(ca.NotAfter) || cert.NotAfter.Sub(cert.NotBefore) > iss.MaxDuration || cert.NotAfter.Sub(cert.NotBefore) > duration {
		t.Fatalf("validity %s to %s (asked %s, max %s, CA until %s)", cert.NotBefore, cert.NotAfter, duration, iss.MaxDuration, ca.NotAfter)
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
	if cn != "" && !contains(cert.DNSNames, cn) || len(cn) > 64 {
		t.Fatalf("common name %q not among %v, or too long", cn, cert.DNSNames)
	}
	if got := cert.Subject.String(); cn == "" && got != "" || cn != "" && got != "CN="+cn {
		t.Fatalf("subject %q holds more than the common name", got)
	}
}

// checkRequestAccepted fails t if an accepted request asked for a CA, an IP
// address or URI, or a usage other than a server certificate's.
func checkRequestAccepted(t *testing.T, isCA bool, tmpl *x509.CertificateRequest, usage string) {
	t.Helper()
	switch {
	case isCA:
		t.Fatal("a CA request was accepted")
	case len(tmpl.IPAddresses)+len(tmpl.URIs) > 0:
		t.Fatal("a request with an IP address or URI was accepted")
	case usage != UsageServerAuth && usage != UsageDigitalSignature && usage != UsageKeyEncipherment:
		t.Fatalf("usage %q was accepted", usage)
	}
}

// fuzzCSR is a CSR for tmpl, or nil if Go won't encode it.
func fuzzCSR(key *ecdsa.PrivateKey, tmpl *x509.CertificateRequest) []byte {
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: csrBlock, Bytes: der})
}

// FuzzTemplateNames signs CSRs whose names, common name, extra SANs, usages and
// duration come from the fuzzer, under a CA whose remaining life does too, and
// checks every accepted one.
func FuzzTemplateNames(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	const day, year = int64(24 * 3600), int64(365 * 24)
	f.Add(testName, testName+","+testDomain, "", "", false, false, 30*day, UsageServerAuth, year)
	f.Add("", testWildcard+",x."+otherDomain, "", "", true, false, int64(3600), UsageDigitalSignature, year)
	f.Add(mixedCaseName, "SSO-Admin.Example.Internal", "", "", false, true, 90*day, UsageKeyEncipherment, year)
	f.Add(evilName, evilName, "", "", false, false, int64(3600), UsageServerAuth, year)
	f.Add(testName, "badexample.internal,example.internal.evil", "10.0.0.1", "https://x.example.internal", false, false, int64(3600), "client auth", year)
	// Each found by fuzzing against a weakened policy: a wildcard without
	// wildcards allowed; a common name that isn't a requested name; a name with a
	// trailing space; a URI SAN; a certificate that would outlive its CA.
	f.Add("", "*."+upperDomain, "", "", false, false, int64(3600), UsageDigitalSignature, year)
	f.Add("0", upperDomain, "", "", false, false, 30*day, UsageServerAuth, year)
	f.Add("", upperDomain+" ", "", "", true, false, int64(3600), UsageDigitalSignature, year)
	f.Add("", otherDomain, "", "0", true, false, int64(3641), UsageDigitalSignature, year)
	f.Add(testName, testName, "", "", false, false, 30*day, UsageServerAuth, int64(10*24))
	f.Fuzz(func(t *testing.T, cn, names, ip, uri string, wildcards, isCA bool, seconds int64, usage string, caHours int64) {
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
		duration := time.Duration(seconds) * time.Second
		req := &Request{CSR: csr, IsCA: isCA, Usages: []string{usage}, Duration: duration, DefaultDuration: time.Hour}
		cert, _, err := Template(req, iss, ca, serial, now)
		if err != nil {
			return
		}
		checkRequestAccepted(t, isCA, tmpl, usage)
		if duration == 0 {
			duration = req.DefaultDuration
		}
		checkIssued(t, cert, iss, ca, duration)
	})
}

// FuzzTemplateCSR hands Template arbitrary request bytes: it must never panic, and
// whatever it accepts must pass the same checks.
func FuzzTemplateCSR(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	for _, tmpl := range []*x509.CertificateRequest{
		{Subject: pkix.Name{CommonName: testName}, DNSNames: []string{testName}},
		{DNSNames: []string{testWildcard, evilName}},
		{Subject: pkix.Name{CommonName: testName, Organization: []string{systemMaster}}, DNSNames: []string{testName}},
	} {
		csr := fuzzCSR(key, tmpl)
		if csr == nil {
			f.Fatal("seed CSR not encoded")
		}
		block, _ := pem.Decode(csr)
		f.Add(csr, false)
		f.Add(block.Bytes, true)
	}
	f.Fuzz(func(t *testing.T, data []byte, wrap bool) {
		if wrap {
			data = pem.EncodeToMemory(&pem.Block{Type: csrBlock, Bytes: data})
		}
		iss := fuzzIssuer(false)
		cert, _, err := Template(&Request{CSR: data, DefaultDuration: 24 * time.Hour}, iss, parent, serial, now)
		if err != nil {
			return
		}
		checkIssued(t, cert, iss, parent, 24*time.Hour)
	})
}
