package certmanager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	fakeclock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	mocks "github.com/sunsofterp/kms-issuer/v5/pkg/kmsmock"
)

var unitNow = time.Date(2026, time.November, 25, 12, 0, 0, 0, time.UTC)

func encodeForTest(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// unitCA is a two-tier CA in a fresh mock: root key, issuing key, root and
// intermediate.
type unitCA struct {
	mock                *mocks.KMSMock
	ca                  *kmsca.KMSCA
	rootKey, issuingKey string
	root, intermediate  *x509.Certificate
}

func newUnitCA(t *testing.T, domains ...string) *unitCA {
	t.Helper()
	if len(domains) == 0 {
		domains = []string{"example.internal"}
	}
	u := &unitCA{mock: mocks.New()}
	u.ca = &kmsca.KMSCA{Client: u.mock}
	var err error
	if u.rootKey, err = u.ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/root", OwnerUID: "t"}); err != nil {
		t.Fatal(err)
	}
	if u.issuingKey, err = u.ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/issuing", OwnerUID: "t"}); err != nil {
		t.Fatal(err)
	}
	in := func(name string, d time.Duration) *kmsca.CAInput {
		return &kmsca.CAInput{Subject: pkix.Name{CommonName: name}, PermittedDNSDomains: domains, Duration: d, Now: unitNow}
	}
	if u.root, err = u.ca.MakeRoot(context.TODO(), u.rootKey, in("Root", 20*365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if u.intermediate, err = u.ca.MakeIntermediate(context.TODO(), u.rootKey, u.root, u.issuingKey, in("Issuing", 90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSettingsValidate(t *testing.T) {
	bad := map[string]settings{
		"under 1h":   {maxCertificateDuration: time.Minute},
		"sub-second": {maxCertificateDuration: time.Hour + time.Millisecond},
	}
	for name, s := range bad {
		if s.validate() == nil {
			t.Errorf("%s: validated", name)
		}
	}
	if err := (settings{maxCertificateDuration: time.Hour}).validate(); err != nil {
		t.Error(err)
	}
}

func TestCheckIssuerCeilings(t *testing.T) {
	u := newUnitCA(t, "fleet.internal")
	access, err := NewAccess([]string{"ca"}, []string{"key-1"}, Ceilings{
		MaxIntermediateDuration: kmsca.MaxIntermediateDuration,
		PermittedDNSDomains:     []string{"fleet.internal"}, MaxCertificateDuration: 90 * 24 * time.Hour,
	}, []*x509.Certificate{u.root}, unitNow)
	if err != nil {
		t.Fatal(err)
	}
	issuer := func(mutate func(*kmsiapi.KMSIssuer)) *kmsiapi.KMSIssuer {
		i := &kmsiapi.KMSIssuer{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ca", Name: "i"},
			Spec:       kmsiapi.KMSIssuerSpec{KeyID: "key-1", PermittedDNSDomains: []string{"fleet.internal"}},
		}
		if mutate != nil {
			mutate(i)
		}
		return i
	}
	if err := access.CheckIssuer(issuer(nil), issuerSettings(issuer(nil))); err != nil {
		t.Errorf("within ceilings: %v", err)
	}
	sub := issuer(func(i *kmsiapi.KMSIssuer) { i.Spec.PermittedDNSDomains = []string{"sso.fleet.internal"} })
	if err := access.CheckIssuer(sub, issuerSettings(sub)); err != nil {
		t.Errorf("a subdomain of the ceiling: %v", err)
	}
	refused := map[string]func(*kmsiapi.KMSIssuer){
		"a TLD":           func(i *kmsiapi.KMSIssuer) { i.Spec.PermittedDNSDomains = []string{"com"} },
		"a parent domain": func(i *kmsiapi.KMSIssuer) { i.Spec.PermittedDNSDomains = []string{"internal"} },
		"a suffix trick":  func(i *kmsiapi.KMSIssuer) { i.Spec.PermittedDNSDomains = []string{"evilfleet.internal"} },
		"one outside":     func(i *kmsiapi.KMSIssuer) { i.Spec.PermittedDNSDomains = []string{"fleet.internal", "example.com"} },
		"wildcards":       func(i *kmsiapi.KMSIssuer) { i.Spec.AllowWildcards = true },
		"longer leaves": func(i *kmsiapi.KMSIssuer) {
			i.Spec.MaxCertificateDuration = &metav1.Duration{Duration: 91 * 24 * time.Hour}
		},
		"another namespace": func(i *kmsiapi.KMSIssuer) { i.Namespace = "other" },
		"another key":       func(i *kmsiapi.KMSIssuer) { i.Spec.KeyID = "key-2" },
	}
	for name, mutate := range refused {
		i := issuer(mutate)
		if err := access.CheckIssuer(i, issuerSettings(i)); err == nil {
			t.Errorf("%s: allowed", name)
		}
	}
	if _, err := NewAccess([]string{"ca"}, []string{"key-1"}, Ceilings{
		MaxIntermediateDuration: kmsca.MaxIntermediateDuration,
		PermittedDNSDomains:     []string{"internal"}, MaxCertificateDuration: time.Hour,
	}, []*x509.Certificate{u.root}, unitNow); err == nil {
		t.Error("a single-label ceiling was accepted")
	}
	if _, err := NewAccess([]string{"ca"}, []string{"key-1"}, Ceilings{
		MaxIntermediateDuration: kmsca.MaxIntermediateDuration,
		PermittedDNSDomains:     []string{"fleet.internal"}, MaxCertificateDuration: time.Hour,
	}, []*x509.Certificate{u.intermediate}, unitNow); err == nil {
		t.Error("an intermediate was accepted as the root")
	}
	if _, err := NewAccess([]string{"ca"}, []string{"key-1"}, Ceilings{
		MaxIntermediateDuration: kmsca.MaxIntermediateDuration,
		PermittedDNSDomains:     []string{"sso.fleet.internal"}, MaxCertificateDuration: time.Hour,
	}, []*x509.Certificate{u.root}, unitNow); err == nil {
		t.Error("a root wider than the operator's domains was accepted")
	}
}

// Two pinned roots (a root replacement): an intermediate from either verifies, and
// the root handed out is the one it chains to.
func TestTwoRoots(t *testing.T) {
	u := newUnitCA(t)
	newRootKey, err := u.ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/new-root", OwnerUID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	newRoot, err := u.ca.MakeRoot(context.TODO(), newRootKey, &kmsca.CAInput{
		Subject: pkix.Name{CommonName: "New Root"}, PermittedDNSDomains: []string{"example.internal"}, Duration: 20 * 365 * 24 * time.Hour, Now: unitNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	newIntermediate, err := u.ca.MakeIntermediate(context.TODO(), newRootKey, newRoot, u.issuingKey, &kmsca.CAInput{
		Subject: pkix.Name{CommonName: "New Issuing"}, PermittedDNSDomains: []string{"example.internal"}, Duration: 90 * 24 * time.Hour, Now: unitNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	access, err := NewAccess([]string{"default"}, []string{u.issuingKey}, testCeilings, []*x509.Certificate{u.root, newRoot}, unitNow)
	if err != nil {
		t.Fatal(err)
	}
	for want, inter := range map[*x509.Certificate]*x509.Certificate{u.root: u.intermediate, newRoot: newIntermediate} {
		issuer := &kmsiapi.KMSIssuer{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "i"},
			Spec: kmsiapi.KMSIssuerSpec{KeyID: u.issuingKey, IntermediateCertificate: string(encodeForTest(inter.Raw)),
				PermittedDNSDomains: []string{"example.internal"}},
		}
		v, err := verifyIssuer(context.TODO(), u.ca, access, issuer, unitNow.Add(time.Hour))
		if err != nil {
			t.Fatalf("%s: %v", inter.Subject, err)
		}
		if !v.root.Equal(want) {
			t.Errorf("%s: chains to %s, want %s", inter.Subject, v.root.Subject, want.Subject)
		}
	}
}

func TestVerifyIssuer(t *testing.T) {
	u := newUnitCA(t)
	access, err := NewAccess([]string{"default"}, []string{u.issuingKey, u.rootKey}, testCeilings, []*x509.Certificate{u.root}, unitNow)
	if err != nil {
		t.Fatal(err)
	}
	issuer := func(keyID string, intermediate []byte, domains ...string) *kmsiapi.KMSIssuer {
		if len(domains) == 0 {
			domains = []string{"example.internal"}
		}
		return &kmsiapi.KMSIssuer{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "i"},
			Spec:       kmsiapi.KMSIssuerSpec{KeyID: keyID, IntermediateCertificate: string(intermediate), PermittedDNSDomains: domains},
		}
	}
	good := encodeForTest(u.intermediate.Raw)
	if _, err := verifyIssuer(context.TODO(), u.ca, access, issuer(u.issuingKey, good), unitNow.Add(time.Hour)); err != nil {
		t.Errorf("good issuer: %v", err)
	}
	cases := map[string]*kmsiapi.KMSIssuer{
		"the root key with the intermediate": issuer(u.rootKey, good),
		"the root as its own intermediate":   issuer(u.rootKey, encodeForTest(u.root.Raw)),
		"two certificates":                   issuer(u.issuingKey, append(append([]byte{}, good...), good...)),
		"garbage":                            issuer(u.issuingKey, []byte("garbage")),
	}
	for name, i := range cases {
		if _, err := verifyIssuer(context.TODO(), u.ca, access, i, unitNow.Add(time.Hour)); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if _, err := verifyIssuer(context.TODO(), u.ca, access, issuer(u.issuingKey, good), u.intermediate.NotAfter.Add(time.Second)); err == nil {
		t.Error("an expired intermediate verified")
	}

	narrow, err := u.ca.MakeIntermediate(context.TODO(), u.rootKey, u.root, u.issuingKey, &kmsca.CAInput{
		Subject: pkix.Name{CommonName: "Narrow"}, PermittedDNSDomains: []string{"sso.example.internal"}, Duration: 48 * time.Hour, Now: unitNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyIssuer(context.TODO(), u.ca, access, issuer(u.issuingKey, encodeForTest(narrow.Raw), "example.internal"), unitNow.Add(time.Hour)); err == nil {
		t.Error("issuer domains wider than its intermediate's constraints verified")
	}
}

// A KMS failure while the intermediate is valid keeps the issuer ready and returns
// the error for a retry with backoff.
func TestKMSErrorKeepsTheIssuerReady(t *testing.T) {
	u := newUnitCA(t)
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, kmsiapi.KMSIssuerReasonIssued, "")
	issuer := &kmsiapi.KMSIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "i"},
		Spec: kmsiapi.KMSIssuerSpec{
			KeyID: u.issuingKey, IntermediateCertificate: string(encodeForTest(u.intermediate.Raw)),
			PermittedDNSDomains: []string{"example.internal"},
		},
		Status: kmsiapi.KMSIssuerStatus{
			Status:      kmsiapi.Status{Conditions: []kmsiapi.Condition{ready}},
			Certificate: encodeForTest(u.intermediate.Raw),
		},
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kmsiapi.AddToScheme(scheme)
	fc := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(issuer).WithStatusSubresource(issuer).Build()
	access, err := NewAccess([]string{"default"}, []string{u.issuingKey}, testCeilings, []*x509.Certificate{u.root}, unitNow)
	if err != nil {
		t.Fatal(err)
	}
	r := &KMSIssuerReconciler{
		Client: fc, Log: logf.Log, Recorder: record.NewFakeRecorder(10),
		KMSCA: &kmsca.KMSCA{Client: failingKMS{u.mock}}, Access: access, Clock: fakeclock.NewFakeClock(unitNow.Add(time.Hour)),
	}
	_, err = r.Reconcile(context.TODO(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(issuer)})
	if err == nil {
		t.Fatal("a KMS error was swallowed: no retry")
	}
	got := &kmsiapi.KMSIssuer{}
	if err := fc.Get(context.TODO(), client.ObjectKeyFromObject(issuer), got); err != nil {
		t.Fatal(err)
	}
	if !got.Status.IsReady() {
		t.Error("the issuer was marked not ready while its intermediate is valid")
	}
}
