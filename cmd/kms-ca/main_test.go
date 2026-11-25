package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	mocks "github.com/sunsofterp/kms-issuer/v5/pkg/kmsmock"
)

func TestRootThenIntermediate(t *testing.T) {
	ca := &kmsca.KMSCA{Client: mocks.New()}
	newCA = func(context.Context, *common) (*kmsca.KMSCA, error) { return ca, nil }
	rootKey, err := ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/root", OwnerUID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	issuingKey, err := ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/issuing", OwnerUID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rootFile, interFile := filepath.Join(dir, "root.pem"), filepath.Join(dir, "intermediate.pem")
	var out bytes.Buffer

	if err := run([]string{"root", "--key-id", rootKey, "--common-name", "Fleet Root", "--domains", "fleet.internal", "--out", rootFile}, &out); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"intermediate", "--root-key-id", rootKey, "--root-certificate", rootFile,
		"--key-id", issuingKey, "--common-name", "Fleet Issuing", "--domains", "fleet.internal", "--out", interFile}, &out); err != nil {
		t.Fatal(err)
	}
	root, err := readCertificate(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := readCertificate(interFile)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ca.PublicKey(context.TODO(), issuingKey)
	if err := kmsca.ValidateIntermediate(inter, kmsca.ExpectedIntermediate{
		Root: root, PublicKey: pub, AllowedDomains: []string{"fleet.internal"}, Now: time.Now(),
	}); err != nil {
		t.Errorf("the intermediate does not validate: %v", err)
	}
	if got := inter.NotAfter.Sub(inter.NotBefore); got != 2*365*24*time.Hour {
		t.Errorf("intermediate validity %s, want the 2-year default", got)
	}
	if !strings.Contains(out.String(), "path length 0") || !strings.Contains(out.String(), "path length 1") {
		t.Errorf("output does not describe both certificates:\n%s", out.String())
	}

	// Never overwriting a file.
	before, _ := os.ReadFile(rootFile)
	if err := run([]string{"root", "--key-id", rootKey, "--common-name", "Again", "--domains", "fleet.internal", "--out", rootFile}, &out); err == nil {
		t.Error("overwrote the root")
	}
	after, _ := os.ReadFile(rootFile)
	if !bytes.Equal(before, after) {
		t.Error("the root file changed")
	}

	if err := run([]string{"intermediate", "--root-key-id", rootKey, "--root-certificate", rootFile,
		"--key-id", issuingKey, "--common-name", "Wide", "--domains", "com", "--out", filepath.Join(dir, "wide.pem")}, &out); err == nil {
		t.Error("made an intermediate wider than the root")
	}
	if err := run([]string{"intermediate", "--root-key-id", rootKey, "--root-certificate", rootFile,
		"--key-id", rootKey, "--common-name", "Same", "--domains", "fleet.internal", "--out", filepath.Join(dir, "same.pem")}, &out); err == nil {
		t.Error("made an intermediate on the root key")
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
