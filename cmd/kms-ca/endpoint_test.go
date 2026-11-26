package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// isolate points the AWS SDK at empty config files and static credentials, so
// nothing outside the test is read and nothing is called.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, k := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_KMS", "AWS_ENDPOINT_URL_STS", "AWS_PROFILE", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	return dir
}

// Every way the AWS configuration can redirect KMS or STS is refused before
// anything is called.
func TestEndpointOverridesRefused(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"AWS_ENDPOINT_URL":     func(t *testing.T, _ string) { t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1") },
		"AWS_ENDPOINT_URL_KMS": func(t *testing.T, _ string) { t.Setenv("AWS_ENDPOINT_URL_KMS", "http://127.0.0.1:1") },
		"AWS_ENDPOINT_URL_STS": func(t *testing.T, _ string) { t.Setenv("AWS_ENDPOINT_URL_STS", "http://127.0.0.1:1") },
		"endpoint_url in the profile": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "config"), "[default]\nendpoint_url = http://127.0.0.1:1\n")
		},
		"a services section for KMS": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "config"),
				"[default]\nservices = evil\n\n[services evil]\nkms =\n  endpoint_url = http://127.0.0.1:1\n")
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			dir := isolate(t)
			set(t, dir)
			c := &common{}
			_, _, err := c.connect(context.Background())
			if err == nil || !strings.Contains(err.Error(), "overrides the") {
				t.Fatalf("not refused: %v", err)
			}
		})
	}
	t.Run("no override", func(t *testing.T) {
		isolate(t)
		cfgErr := refuseEndpointOverridesFor(t)
		if cfgErr != nil {
			t.Fatalf("refused the default configuration: %v", cfgErr)
		}
	})
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

// refuseEndpointOverridesFor checks the configuration as loaded now, without
// calling AWS.
func refuseEndpointOverridesFor(t *testing.T) error {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return refuseEndpointOverrides(cfg)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
