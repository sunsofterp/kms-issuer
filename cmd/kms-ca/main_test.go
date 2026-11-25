package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	mocks "github.com/sunsofterp/kms-issuer/v5/pkg/kmsmock"
)

type fixture struct {
	ca                  *kmsca.KMSCA
	rootKey, issuingKey string
	dir, rootFile       string
	out                 bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{ca: &kmsca.KMSCA{Client: mocks.New()}, dir: t.TempDir()}
	newCA = func(context.Context, *common) (*kmsca.KMSCA, string, error) {
		return f.ca, "arn:aws:iam::111122223333:user/test", nil
	}
	var err error
	if f.rootKey, err = f.ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/root", OwnerUID: "t"}); err != nil {
		t.Fatal(err)
	}
	if f.issuingKey, err = f.ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/issuing", OwnerUID: "t"}); err != nil {
		t.Fatal(err)
	}
	f.rootFile = filepath.Join(f.dir, "root.pem")
	if err := run([]string{"root", "--key-id", f.rootKey, "--common-name", "Fleet Root", "--domains", "fleet.internal", "--out", f.rootFile}, &f.out); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) intermediate(out string, extra ...string) error {
	args := append([]string{"intermediate", "--root-key-id", f.rootKey, "--root-certificate", f.rootFile,
		"--key-id", f.issuingKey, "--common-name", "Fleet Issuing", "--domains", "fleet.internal", "--out", out}, extra...)
	return run(args, &f.out)
}

func TestRootThenIntermediate(t *testing.T) {
	f := newFixture(t)
	interFile := filepath.Join(f.dir, "intermediate.pem")
	if err := f.intermediate(interFile); err != nil {
		t.Fatal(err)
	}
	root, err := readCertificate(f.rootFile)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := readCertificate(interFile)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := f.ca.PublicKey(context.TODO(), f.issuingKey)
	if _, err := kmsca.ValidateIntermediate(inter, kmsca.ExpectedIntermediate{
		Roots: []*x509.Certificate{root}, PublicKey: pub, AllowedDomains: []string{"fleet.internal"}, Now: time.Now(),
	}); err != nil {
		t.Errorf("the intermediate does not validate: %v", err)
	}
	if got := inter.NotAfter.Sub(inter.NotBefore); got != kmsca.MaxIntermediateDuration {
		t.Errorf("intermediate validity %s, want the %s default", got, kmsca.MaxIntermediateDuration)
	}
	for _, want := range []string{"path length 0", "path length 1", "server auth", "public key sha256", f.rootKey, "arn:aws:iam::111122223333:user/test"} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, f.out.String())
		}
	}
}

func TestRefusals(t *testing.T) {
	f := newFixture(t)
	before, _ := os.ReadFile(f.rootFile)
	if err := run([]string{"root", "--key-id", f.rootKey, "--common-name", "Again", "--domains", "fleet.internal", "--out", f.rootFile}, &f.out); err == nil {
		t.Error("overwrote the root")
	}
	if after, _ := os.ReadFile(f.rootFile); !bytes.Equal(before, after) {
		t.Error("the root file changed")
	}

	refused := map[string][]string{
		"a TLD as root domain":      {"root", "--key-id", f.rootKey, "--common-name", "R", "--domains", "com", "--out", filepath.Join(f.dir, "tld.pem")},
		"a wildcard root domain":    {"root", "--key-id", f.rootKey, "--common-name", "R", "--domains", "*.fleet.internal", "--out", filepath.Join(f.dir, "wild.pem")},
		"an upper-case root domain": {"root", "--key-id", f.rootKey, "--common-name", "R", "--domains", "Fleet.Internal", "--out", filepath.Join(f.dir, "upper.pem")},
		"an alias as key":           {"root", "--key-id", "alias/root", "--common-name", "R", "--domains", "fleet.internal", "--out", filepath.Join(f.dir, "alias.pem")},
	}
	for name, args := range refused {
		if err := run(args, &f.out); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(args[len(args)-1]); err == nil {
			t.Errorf("%s: left a file behind", name)
		}
	}

	intermediates := map[string][]string{
		"wider than the root":     {"--domains", "other.internal"},
		"longer than 183 days":    {"--duration", "8760h"},
		"the root's name":         {"--common-name", "Fleet Root"},
		"an alias as root key":    {"--root-key-id", "alias/root"},
		"the root key as issuing": {"--key-id", f.rootKey},
	}
	for name, extra := range intermediates {
		out := filepath.Join(f.dir, strings.ReplaceAll(name, " ", "-")+".pem")
		if err := f.intermediate(out, extra...); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: left a file behind", name)
		}
	}
}

func TestUsage(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{nil, {"bogus"}, {"root"}, {"show"}} {
		if err := run(args, &out); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
