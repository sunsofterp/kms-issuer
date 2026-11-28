package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	mocks "github.com/sunsofterp/kms-issuer/v5/pkg/kmsmock"
)

const (
	flagKeyID      = "--key-id"
	flagCommonName = "--common-name"
	flagDomains    = "--domains"
	flagOut        = "--out"
	flagRootKeyID  = "--root-key-id"
	rootAlias      = "alias/root"
	testDomain     = "fleet.internal"
	testIdentity   = "arn:aws:iam::111122223333:user/test"
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
		return f.ca, testIdentity, nil
	}
	var err error
	if f.rootKey, err = f.ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: rootAlias, OwnerUID: "t"}); err != nil {
		t.Fatal(err)
	}
	if f.issuingKey, err = f.ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/issuing", OwnerUID: "t"}); err != nil {
		t.Fatal(err)
	}
	f.rootFile = filepath.Join(f.dir, "root.pem")
	if err := run(rootArgs(f.rootKey, "Fleet Root", testDomain, f.rootFile), &f.out); err != nil {
		t.Fatal(err)
	}
	return f
}

// rootArgs is a `kms-ca root` command line.
func rootArgs(keyID, commonName, domains, out string) []string {
	return []string{cmdRoot, flagKeyID, keyID, flagCommonName, commonName, flagDomains, domains, flagOut, out}
}

func (f *fixture) intermediate(out string, extra ...string) error {
	return run(f.intermediateArgs(out, extra...), &f.out)
}

// intermediateArgs is a `kms-ca intermediate` command line.
func (f *fixture) intermediateArgs(out string, extra ...string) []string {
	return append([]string{cmdIntermediate, flagRootKeyID, f.rootKey, "--root-certificate", f.rootFile,
		flagKeyID, f.issuingKey, flagCommonName, "Fleet Issuing", flagDomains, testDomain, flagOut, out}, extra...)
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
	if _, err := kmsca.ValidateIntermediate(inter, &kmsca.ExpectedIntermediate{
		Roots: []*x509.Certificate{root}, PublicKey: pub, AllowedDomains: []string{testDomain}, Now: time.Now(),
	}); err != nil {
		t.Errorf("the intermediate does not validate: %v", err)
	}
	if got := inter.NotAfter.Sub(inter.NotBefore); got != kmsca.MaxIntermediateDuration {
		t.Errorf("intermediate validity %s, want the %s default", got, kmsca.MaxIntermediateDuration)
	}
	for _, want := range []string{"path length 0", "path length 1", "server auth", "public key sha256", f.rootKey, testIdentity} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, f.out.String())
		}
	}
}

func TestRefusals(t *testing.T) {
	f := newFixture(t)
	before, _ := os.ReadFile(f.rootFile)
	if err := run(rootArgs(f.rootKey, "Again", testDomain, f.rootFile), &f.out); err == nil {
		t.Error("overwrote the root")
	}
	if after, _ := os.ReadFile(f.rootFile); !bytes.Equal(before, after) {
		t.Error("the root file changed")
	}

	refused := map[string][]string{
		"a TLD as root domain":      rootArgs(f.rootKey, "R", "com", filepath.Join(f.dir, "tld.pem")),
		"a wildcard root domain":    rootArgs(f.rootKey, "R", "*.fleet.internal", filepath.Join(f.dir, "wild.pem")),
		"an upper-case root domain": rootArgs(f.rootKey, "R", "Fleet.Internal", filepath.Join(f.dir, "upper.pem")),
		"an alias as key":           rootArgs(rootAlias, "R", testDomain, filepath.Join(f.dir, "alias.pem")),
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
		"wider than the root":     {flagDomains, "other.internal"},
		"longer than 183 days":    {"--duration", "8760h"},
		"the root's name":         {flagCommonName, "Fleet Root"},
		"an alias as root key":    {flagRootKeyID, rootAlias},
		"the root key as issuing": {flagKeyID, f.rootKey},
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
	for _, args := range [][]string{nil, {"bogus"}, {cmdRoot}, {"show"}} {
		if err := run(args, &out); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}

// failingWriter accepts ok writes, then fails every write.
type failingWriter struct{ ok int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.ok > 0 {
		w.ok--
		return len(p), nil
	}
	return 0, os.ErrClosed
}

// A summary that can't be printed after the certificate is written says it was
// written, so the administrator doesn't sign again: whether the heading fails or
// a later line of the summary does.
func TestSummaryFailureSaysWritten(t *testing.T) {
	f := newFixture(t)
	for _, ok := range []int{0, 1} {
		root := filepath.Join(f.dir, fmt.Sprintf("root-%d.pem", ok))
		err := run(rootArgs(f.rootKey, "Fleet Root 2", testDomain, root), &failingWriter{ok: ok})
		if err == nil || !strings.Contains(err.Error(), "the certificate was written to "+root) {
			t.Errorf("root, failing after %d writes: %v, want it to say the certificate was written", ok, err)
		}
		if _, statErr := os.Stat(root); statErr != nil {
			t.Errorf("root: %v", statErr)
		}
		inter := filepath.Join(f.dir, fmt.Sprintf("inter-%d.pem", ok))
		if err := run(f.intermediateArgs(inter), &failingWriter{ok: ok}); err == nil || !strings.Contains(err.Error(), "the certificate was written to "+inter) {
			t.Errorf("intermediate, failing after %d writes: %v, want it to say the certificate was written", ok, err)
		}
	}
}

// closeFailing is an output file whose Close fails.
type closeFailing struct{ bytes.Buffer }

func (*closeFailing) Close() error { return os.ErrClosed }
func (*closeFailing) Name() string { return "/ca/inter.pem" }

// A file that can't be closed after the certificate is written says so.
func TestCloseFailureSaysWritten(t *testing.T) {
	f := newFixture(t)
	root, err := readCertificate(f.rootFile)
	if err != nil {
		t.Fatal(err)
	}
	out := &closeFailing{}
	err = finish(out, root)
	if err == nil || !strings.Contains(err.Error(), "the certificate was signed and written to /ca/inter.pem") || !errors.Is(err, os.ErrClosed) {
		t.Errorf("%v, want it to say the certificate was written", err)
	}
	if out.Len() == 0 {
		t.Error("nothing was written")
	}
}

// The path reported is the one written.
func TestReportsThePathWritten(t *testing.T) {
	f := newFixture(t)
	if err := os.Mkdir(filepath.Join(f.dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(f.dir, "sub") + "/../"
	for name, write := range map[string]func(string) error{
		cmdRoot:         func(out string) error { return run(rootArgs(f.rootKey, "Fleet Root 2", testDomain, out), &f.out) },
		cmdIntermediate: func(out string) error { return f.intermediate(out) },
	} {
		f.out.Reset()
		if err := write(sub + name + "-2.pem"); err != nil {
			t.Fatal(err)
		}
		written := filepath.Join(f.dir, name+"-2.pem")
		if !strings.Contains(f.out.String(), "wrote "+written+"\n") {
			t.Errorf("%s: output %q does not name %s", name, f.out.String(), written)
		}
	}
}
