package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
)

// isolate points the AWS SDK at empty config files and static credentials, so
// nothing outside the test is read. The tests below only load the configuration
// (loadConfig), which calls nothing: even if a refusal regressed, no request
// would be made. The two exceptions talk only to loopback listeners or to a
// .invalid name.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if upper := strings.ToUpper(name); strings.HasPrefix(name, "AWS_") || strings.HasSuffix(upper, "_PROXY") || strings.HasPrefix(upper, "SSL_CERT_") {
			t.Setenv(name, "")
			os.Unsetenv(name)
		}
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	return dir
}

// Everything that could redirect a call, or make it trust another CA, is refused.
func TestRedirectsRefused(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"AWS_ENDPOINT_URL":          func(t *testing.T, _ string) { t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1") },
		"AWS_ENDPOINT_URL_KMS":      func(t *testing.T, _ string) { t.Setenv("AWS_ENDPOINT_URL_KMS", "http://127.0.0.1:1") },
		"AWS_ENDPOINT_URL_STS":      func(t *testing.T, _ string) { t.Setenv("AWS_ENDPOINT_URL_STS", "http://127.0.0.1:1") },
		"AWS_ENDPOINT_URL_SSO":      func(t *testing.T, _ string) { t.Setenv("AWS_ENDPOINT_URL_SSO", "http://127.0.0.1:1") },
		"AWS_ENDPOINT_URL_SSO_OIDC": func(t *testing.T, _ string) { t.Setenv("AWS_ENDPOINT_URL_SSO_OIDC", "http://127.0.0.1:1") },
		"SSL_CERT_FILE": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "ca.pem"), testCAPEM(t))
			t.Setenv("SSL_CERT_FILE", filepath.Join(dir, "ca.pem"))
		},
		"SSL_CERT_DIR": func(t *testing.T, dir string) { t.Setenv("SSL_CERT_DIR", dir) },
		"AWS_CA_BUNDLE": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "ca.pem"), testCAPEM(t))
			t.Setenv("AWS_CA_BUNDLE", filepath.Join(dir, "ca.pem"))
		},
		"ca_bundle in the profile": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "ca.pem"), testCAPEM(t))
			writeFile(t, filepath.Join(dir, "config"), "[default]\nca_bundle = "+filepath.Join(dir, "ca.pem")+"\n")
		},
		"endpoint_url in the profile": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "config"), "[default]\nendpoint_url = http://127.0.0.1:1\n")
		},
		"a services section for KMS": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "config"),
				"[default]\nservices = evil\n\n[services evil]\nkms =\n  endpoint_url = http://127.0.0.1:1\n")
		},
		"a services section for SSO": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "config"),
				"[default]\nservices = evil\n\n[services evil]\nsso =\n  endpoint_url = http://127.0.0.1:1\n")
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			dir := isolate(t)
			set(t, dir)
			c := &common{}
			if _, err := c.loadConfig(context.Background()); err == nil || !strings.Contains(err.Error(), "clean environment") {
				t.Fatalf("not refused: %v", err)
			}
		})
	}
	t.Run("nothing set", func(t *testing.T) {
		isolate(t)
		c := &common{}
		if _, err := c.loadConfig(context.Background()); err != nil {
			t.Fatalf("refused a clean configuration: %v", err)
		}
	})
}

// Proxy settings are ignored by every client the configuration builds.
func TestProxyIgnored(t *testing.T) {
	isolate(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	c := &common{}
	cfg, err := c.loadConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	client, ok := cfg.HTTPClient.(*awshttp.BuildableClient)
	if !ok {
		t.Fatalf("HTTP client is %T", cfg.HTTPClient)
	}
	if client.GetTransport().Proxy != nil {
		t.Error("the transport still uses a proxy")
	}
}

// listener counts the connections made to it and closes each at once.
func listener(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var hits atomic.Int32
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			conn.Close()
		}
	}()
	return "http://" + l.Addr().String(), &hits
}

// The container credential provider (ECS, EKS Pod Identity) builds its own HTTP
// client unless told otherwise: it must not go through the proxy either. The
// credential URI is a .invalid name, so the fetch fails at name resolution
// without the proxy and reaches nothing.
func TestContainerCredentialsIgnoreProxy(t *testing.T) {
	isolate(t)
	proxy, hits := listener(t)
	t.Setenv("HTTPS_PROXY", proxy)
	t.Setenv("HTTP_PROXY", proxy)
	os.Unsetenv("AWS_ACCESS_KEY_ID")
	os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "https://creds.invalid/credentials")
	c := &common{}
	cfg, err := c.loadConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cfg.Credentials.Retrieve(ctx); err == nil {
		t.Fatal("credentials retrieved from creds.invalid")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the credential fetch went through the proxy (%d connections)", n)
	}
}

// AWS_DEFAULTS_MODE=auto would make loading the configuration ask the instance
// metadata service: release builds pin the standard mode, so nothing is called.
func TestDefaultsModeAutoCallsNothing(t *testing.T) {
	isolate(t)
	imds, hits := listener(t)
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imds)
	t.Setenv("AWS_DEFAULTS_MODE", "auto")
	t.Setenv("AWS_ENDPOINT_URL_KMS", "http://127.0.0.1:1")
	c := &common{}
	if _, err := c.loadConfig(context.Background()); err == nil {
		t.Fatal("AWS_ENDPOINT_URL_KMS not refused")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("loading the configuration called the metadata service (%d connections)", n)
	}
}

// The endpoint printed follows the FIPS setting.
func TestResolvedEndpoint(t *testing.T) {
	isolate(t)
	c := &common{}
	cfg, err := c.loadConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ep, err := resolvedKMSEndpoint(context.Background(), cfg)
	if err != nil || ep != "https://kms.us-east-1.amazonaws.com" {
		t.Errorf("endpoint %q, %v", ep, err)
	}
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	if cfg, err = c.loadConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ep, _ = resolvedKMSEndpoint(context.Background(), cfg); !strings.Contains(ep, "kms-fips.") {
		t.Errorf("FIPS endpoint %q", ep)
	}
}

// A release (untagged) build has no --aws-endpoint flag.
func TestNoTestEndpointFlag(t *testing.T) {
	if registerTestEndpoint != nil {
		t.Skip("built with the kmsca_test_endpoint tag")
	}
	err := run([]string{"root", "--aws-endpoint", "http://127.0.0.1:1", "--key-id", "k", "--common-name", "R", "--domains", "fleet.internal",
		"--out", filepath.Join(t.TempDir(), "r.pem")}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "aws-endpoint") {
		t.Fatalf("--aws-endpoint accepted: %v", err)
	}
}

// testCAPEM is a throwaway self-signed CA certificate, as a CA bundle would hold.
func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Interception CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
