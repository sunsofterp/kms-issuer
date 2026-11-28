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
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testDomain     = "example.internal"
	testName       = "a.example.internal"
	testWildcard   = "*.example.internal"
	mixedCaseName  = "SSO-Admin.example.internal"
	usageClientAut = "client auth"
	usageCertSign  = "cert sign"
	usageCodeSign  = "code signing"
)

var (
	now    = time.Date(2026, time.November, 25, 12, 0, 0, 0, time.UTC)
	serial = big.NewInt(42)
	parent = &x509.Certificate{IsCA: true, NotAfter: now.Add(365 * 24 * time.Hour)}
	issuer = &Issuer{PermittedDNSDomains: []string{testDomain}, MaxDuration: 90 * 24 * time.Hour}
)

func csrPEM(t *testing.T, key crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: csrBlock, Bytes: der})
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTemplateIssuesAServerCertificate(t *testing.T) {
	key := rsaKey(t, 2048)
	req := &Request{
		CSR: csrPEM(t, key, &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: mixedCaseName, Organization: []string{systemMaster}},
			DNSNames: []string{mixedCaseName, "other.example.internal", testDomain},
		}),
		Usages:          []string{UsageDigitalSignature, UsageKeyEncipherment, UsageServerAuth},
		DefaultDuration: 90 * 24 * time.Hour,
	}
	cert, pub, err := Template(req, issuer, parent, serial, now)
	if err != nil {
		t.Fatal(err)
	}
	if cert.IsCA || !cert.BasicConstraintsValid {
		t.Error("issued certificate must be a non-CA with basic constraints")
	}
	if cert.Subject.String() != "CN=sso-admin.example.internal" {
		t.Errorf("subject = %q, want only the lower-cased common name", cert.Subject.String())
	}
	if got := strings.Join(cert.DNSNames, ","); got != "sso-admin.example.internal,other.example.internal,example.internal" {
		t.Errorf("DNS names = %s", got)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("key usage = %v", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ext key usage = %v", cert.ExtKeyUsage)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != 90*24*time.Hour {
		t.Errorf("validity = %s, want exactly the requested 2160h", got)
	}
	if !cert.NotBefore.Before(now) {
		t.Errorf("notBefore = %s, want slightly before now", cert.NotBefore)
	}
	if !key.PublicKey.Equal(pub) {
		t.Error("public key is not the CSR's")
	}
	if len(cert.ExtraExtensions) != 0 || len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses) != 0 {
		t.Error("nothing from the request may be copied beyond the checked fields")
	}
}

func TestTemplateClampsToTheCA(t *testing.T) {
	key := rsaKey(t, 2048)
	shortParent := &x509.Certificate{IsCA: true, NotAfter: now.Add(10 * 24 * time.Hour)}
	req := &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testName}}), DefaultDuration: 90 * 24 * time.Hour}
	cert, _, err := Template(req, issuer, shortParent, serial, now)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(shortParent.NotAfter) {
		t.Errorf("notAfter = %s, want the CA's %s", cert.NotAfter, shortParent.NotAfter)
	}
	expired := &x509.Certificate{IsCA: true, NotAfter: now.Add(-time.Hour)}
	if _, _, err := Template(req, issuer, expired, serial, now); err == nil {
		t.Error("issued under an expired CA")
	}
}

func TestTemplateAcceptsOtherKeyTypes(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	for name, key := range map[string]crypto.Signer{"ecdsa": ec, "ed25519": ed} {
		req := &Request{
			CSR:             csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testName}}),
			Usages:          []string{UsageDigitalSignature, UsageKeyEncipherment},
			DefaultDuration: time.Hour,
		}
		cert, _, err := Template(req, issuer, parent, serial, now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cert.KeyUsage != x509.KeyUsageDigitalSignature {
			t.Errorf("%s: key usage = %v, want digital signature only", name, cert.KeyUsage)
		}
	}
}

func TestTemplateRefuses(t *testing.T) {
	key := rsaKey(t, 2048)
	small := rsaKey(t, 1024)
	ec224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	uri, _ := url.Parse("spiffe://example.internal/x")
	good := func() *x509.CertificateRequest {
		return &x509.CertificateRequest{DNSNames: []string{testName}}
	}
	otherName := func() *x509.CertificateRequest {
		// A SAN extension holding an otherName [0] alongside a DNS name.
		raw, _ := asn1.Marshal([]asn1.RawValue{
			{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(testName)},
			{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{0x06, 0x01, 0x2a, 0xa0, 0x02, 0x0c, 0x00}},
		})
		return &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Value: raw}}}
	}
	tests := map[string]struct {
		req    *Request
		issuer *Issuer
	}{
		"a CA":                     {req: &Request{CSR: csrPEM(t, key, good()), IsCA: true, DefaultDuration: time.Hour}},
		"a name outside":           {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{"accounts.google.com"}}), DefaultDuration: time.Hour}},
		"a suffix trick":           {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{"evilexample.internal"}}), DefaultDuration: time.Hour}},
		"one bad name among good":  {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testName, "*.com"}}), DefaultDuration: time.Hour}},
		"a wildcard by default":    {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testWildcard}}), DefaultDuration: time.Hour}},
		"a bad hostname":           {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{"a_b.example.internal"}}), DefaultDuration: time.Hour}},
		"a trailing dot":           {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{"a.example.internal."}}), DefaultDuration: time.Hour}},
		"no DNS name":              {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: testName}}), DefaultDuration: time.Hour}},
		"a common name not a SAN":  {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: evilName}, DNSNames: []string{testName}}), DefaultDuration: time.Hour}},
		"an IP address":            {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testName}, IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)}}), DefaultDuration: time.Hour}},
		"a URI":                    {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testName}, URIs: []*url.URL{uri}}), DefaultDuration: time.Hour}},
		"an email address":         {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testName}, EmailAddresses: []string{"a@example.internal"}}), DefaultDuration: time.Hour}},
		"an otherName SAN":         {req: &Request{CSR: csrPEM(t, key, otherName()), DefaultDuration: time.Hour}},
		usageClientAut:             {req: &Request{CSR: csrPEM(t, key, good()), Usages: []string{usageClientAut}, DefaultDuration: time.Hour}},
		usageCertSign:              {req: &Request{CSR: csrPEM(t, key, good()), Usages: []string{usageCertSign}, DefaultDuration: time.Hour}},
		usageCodeSign:              {req: &Request{CSR: csrPEM(t, key, good()), Usages: []string{usageCodeSign}, DefaultDuration: time.Hour}},
		"a bad second usage":       {req: &Request{CSR: csrPEM(t, key, good()), Usages: []string{UsageServerAuth, usageClientAut}, DefaultDuration: time.Hour}},
		"data after the request":   {req: &Request{CSR: append(csrPEM(t, key, good()), "junk\n"...), DefaultDuration: time.Hour}},
		"a 64-character label":     {req: &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{strings.Repeat("a", 64) + "." + testDomain}}), DefaultDuration: time.Hour}},
		"too long":                 {req: &Request{CSR: csrPEM(t, key, good()), Duration: 91 * 24 * time.Hour}},
		"twenty years":             {req: &Request{CSR: csrPEM(t, key, good()), Duration: 20 * 365 * 24 * time.Hour}},
		"too short":                {req: &Request{CSR: csrPEM(t, key, good()), Duration: time.Minute}},
		"a small RSA key":          {req: &Request{CSR: csrPEM(t, small, good()), DefaultDuration: time.Hour}},
		"a weak curve":             {req: &Request{CSR: csrPEM(t, ec224, good()), DefaultDuration: time.Hour}},
		"garbage":                  {req: &Request{CSR: []byte("not a csr"), DefaultDuration: time.Hour}},
		"an issuer with no domain": {req: &Request{CSR: csrPEM(t, key, good()), DefaultDuration: time.Hour}, issuer: &Issuer{MaxDuration: time.Hour * 24}},
		"an issuer with no max":    {req: &Request{CSR: csrPEM(t, key, good()), DefaultDuration: time.Hour}, issuer: &Issuer{PermittedDNSDomains: []string{testDomain}}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			iss := tc.issuer
			if iss == nil {
				iss = issuer
			}
			cert, _, err := Template(tc.req, iss, parent, serial, now)
			if err == nil {
				t.Fatalf("issued %v; want refused", cert.DNSNames)
			}
			if !errors.Is(err, ErrDenied) {
				t.Errorf("error %v does not wrap ErrDenied", err)
			}
		})
	}
}

// RSA keys over the upper bound are refused (built by hand: generating one takes
// minutes); the bound itself is accepted.
func TestPublicKeyRSABounds(t *testing.T) {
	for bits, ok := range map[int]bool{maxRSABits: true, maxRSABits + 1: false} {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		_, err := checkPublicKey(&rsa.PublicKey{N: n.Add(n, big.NewInt(1)), E: 65537})
		if (err == nil) != ok {
			t.Errorf("a %d-bit RSA key: %v", bits, err)
		}
	}
}

func TestTemplateTamperedCSR(t *testing.T) {
	key := rsaKey(t, 2048)
	block, _ := pem.Decode(csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testName}}))
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	req := &Request{CSR: pem.EncodeToMemory(block), DefaultDuration: time.Hour}
	if _, _, err := Template(req, issuer, parent, serial, now); !errors.Is(err, ErrDenied) {
		t.Errorf("tampered CSR: err = %v, want refused", err)
	}
}

func TestTemplateWildcardsWhenAllowed(t *testing.T) {
	key := rsaKey(t, 2048)
	iss := &Issuer{PermittedDNSDomains: []string{testDomain}, AllowWildcards: true, MaxDuration: time.Hour * 24}
	req := &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testWildcard}}), DefaultDuration: time.Hour}
	if _, _, err := Template(req, iss, parent, serial, now); err != nil {
		t.Fatal(err)
	}
	bad := &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{"*.*.example.internal"}}), DefaultDuration: time.Hour}
	if _, _, err := Template(bad, iss, parent, serial, now); err == nil {
		t.Error("issued a double wildcard")
	}
	outside := &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{"*.internal"}}), DefaultDuration: time.Hour}
	if _, _, err := Template(outside, iss, parent, serial, now); err == nil {
		t.Error("issued a wildcard above the permitted domain")
	}
}

func TestTemplateCommonNameLimit(t *testing.T) {
	key := rsaKey(t, 2048)
	long := strings.Repeat("a", 60) + ".example.internal"
	req := &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: long}, DNSNames: []string{long}}), DefaultDuration: time.Hour}
	if _, _, err := Template(req, issuer, parent, serial, now); !errors.Is(err, ErrDenied) {
		t.Errorf("a %d-character common name: err = %v, want refused", len(long), err)
	}
	req = &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{long}}), DefaultDuration: time.Hour}
	if _, _, err := Template(req, issuer, parent, serial, now); err != nil {
		t.Errorf("the same name without a common name: %v", err)
	}
	// The longest label allowed (TestTemplateRefuses: one longer).
	label := strings.Repeat("a", 63) + "." + testDomain
	req = &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{label}}), DefaultDuration: time.Hour}
	if _, _, err := Template(req, issuer, parent, serial, now); err != nil {
		t.Errorf("a 63-character label: %v", err)
	}
}

// Near the intermediate's expiry, certificates are cut short; below an hour, the
// request waits (not refused) for a renewed intermediate.
func TestTemplateIntermediateTooCloseToExpiry(t *testing.T) {
	key := rsaKey(t, 2048)
	soon := &x509.Certificate{IsCA: true, NotAfter: now.Add(30 * time.Minute)}
	req := &Request{CSR: csrPEM(t, key, &x509.CertificateRequest{DNSNames: []string{testName}}), DefaultDuration: 24 * time.Hour}
	_, _, err := Template(req, issuer, soon, serial, now)
	if err == nil {
		t.Fatal("issued a 30-minute certificate")
	}
	if errors.Is(err, ErrDenied) {
		t.Errorf("refused for good (%v); it should wait for a renewed intermediate", err)
	}
}
