package certmanager

import (
	"context"
	"crypto/x509/pkix"
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

func TestNeedsNewCA(t *testing.T) {
	ca := &kmsca.KMSCA{Client: mocks.New()}
	keyID, err := ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/needs-new-ca", OwnerUID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	s := settings{duration: 10 * 24 * time.Hour, renewBefore: 2 * 24 * time.Hour, maxCertificateDuration: time.Hour}
	cert, err := ca.GenerateAndSignCertificateAuthorityCertificate(context.TODO(), &kmsca.GenerateCertificateAuthorityCertificateInput{
		KeyID: keyID, Subject: pkix.Name{CommonName: "Root"}, Duration: s.duration,
		PermittedDNSDomains: []string{"example.internal"}, Now: unitNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ca.PublicKey(context.TODO(), keyID)
	if err != nil {
		t.Fatal(err)
	}
	expected := func(now time.Time, domains ...string) kmsca.ExpectedCA {
		if len(domains) == 0 {
			domains = []string{"example.internal"}
		}
		return kmsca.ExpectedCA{PublicKey: pub, CommonName: "Root", PermittedDNSDomains: domains, Now: now}
	}

	if reason := needsNewCA(cert, s, expected(unitNow)); reason != "" {
		t.Errorf("fresh certificate: %s", reason)
	}
	if reason := needsNewCA(cert, s, expected(unitNow.Add(7*24*time.Hour))); reason != "" {
		t.Errorf("before renewal: %s", reason)
	}
	if reason := needsNewCA(cert, s, expected(unitNow.Add(8*24*time.Hour))); reason == "" {
		t.Error("renewal due: no new CA")
	}
	if reason := needsNewCA(nil, s, expected(unitNow)); reason == "" {
		t.Error("no certificate: no new CA")
	}
	if reason := needsNewCA(cert, s, expected(unitNow, "example.internal", "other.internal")); reason == "" {
		t.Error("domains changed: no new CA")
	}
	longer := s
	longer.duration = 20 * 24 * time.Hour
	if reason := needsNewCA(cert, longer, expected(unitNow)); reason == "" {
		t.Error("duration changed: no new CA")
	}
	tampered := *cert
	tampered.MaxPathLenZero = false
	tampered.MaxPathLen = -1
	if reason := needsNewCA(&tampered, s, expected(unitNow)); reason == "" {
		t.Error("unconstrained path length: no new CA")
	}
}

func TestSettingsValidate(t *testing.T) {
	bad := map[string]settings{
		"duration under 24h":        {duration: time.Hour, renewBefore: 0, maxCertificateDuration: time.Hour},
		"renewBefore == duration":   {duration: 48 * time.Hour, renewBefore: 48 * time.Hour, maxCertificateDuration: time.Hour},
		"renewBefore near duration": {duration: 24 * time.Hour, renewBefore: 23*time.Hour + 57*time.Minute, maxCertificateDuration: time.Hour},
		"negative renewBefore":      {duration: 48 * time.Hour, renewBefore: -time.Hour, maxCertificateDuration: time.Hour},
		"max under 1h":              {duration: 48 * time.Hour, renewBefore: time.Hour, maxCertificateDuration: time.Minute},
		"sub-second duration":       {duration: 87600*time.Hour + 500*time.Millisecond, renewBefore: time.Hour, maxCertificateDuration: time.Hour},
		"sub-second renewBefore":    {duration: 48 * time.Hour, renewBefore: time.Hour + time.Millisecond, maxCertificateDuration: time.Hour},
	}
	for name, s := range bad {
		if s.validate() == nil {
			t.Errorf("%s: validated", name)
		}
	}
	good := settings{duration: 48 * time.Hour, renewBefore: 24 * time.Hour, maxCertificateDuration: time.Hour}
	if err := good.validate(); err != nil {
		t.Error(err)
	}
}

func TestCheckIssuerCeilings(t *testing.T) {
	access, err := NewAccess([]string{"ca"}, []string{"key-1"}, Ceilings{
		PermittedDNSDomains: []string{"fleet.internal"}, MaxCertificateDuration: 90 * 24 * time.Hour, MaxCADuration: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer := func(mutate func(*kmsiapi.KMSIssuer)) *kmsiapi.KMSIssuer {
		i := &kmsiapi.KMSIssuer{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ca", Name: "i"},
			Spec:       kmsiapi.KMSIssuerSpec{KeyID: "key-1", CommonName: "Root", PermittedDNSDomains: []string{"fleet.internal"}},
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
		"a longer CA":       func(i *kmsiapi.KMSIssuer) { i.Spec.Duration = &metav1.Duration{Duration: 11 * 365 * 24 * time.Hour} },
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
		PermittedDNSDomains: []string{"internal"}, MaxCertificateDuration: time.Hour, MaxCADuration: 48 * time.Hour,
	}); err == nil {
		t.Error("a single-label ceiling was accepted")
	}
}

// A KMS failure while a valid CA certificate is stored keeps the issuer ready and
// returns the error for a retry with backoff.
func TestKMSErrorKeepsTheIssuerReady(t *testing.T) {
	mock := mocks.New()
	ca := &kmsca.KMSCA{Client: mock}
	keyID, err := ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/kms-error", OwnerUID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.GenerateAndSignCertificateAuthorityCertificate(context.TODO(), &kmsca.GenerateCertificateAuthorityCertificateInput{
		KeyID: keyID, Subject: pkix.Name{CommonName: "Root"}, Duration: defaultCertDuration,
		PermittedDNSDomains: []string{"example.internal"}, Now: unitNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, kmsiapi.KMSIssuerReasonIssued, "")
	issuer := &kmsiapi.KMSIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "i"},
		Spec:       kmsiapi.KMSIssuerSpec{KeyID: keyID, CommonName: "Root", PermittedDNSDomains: []string{"example.internal"}},
		Status: kmsiapi.KMSIssuerStatus{
			Status:      kmsiapi.Status{Conditions: []kmsiapi.Condition{ready}},
			Certificate: kmsca.EncodeCertificatePEM(cert),
		},
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kmsiapi.AddToScheme(scheme)
	fc := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(issuer).WithStatusSubresource(issuer).Build()
	access, err := NewAccess([]string{"default"}, []string{keyID}, testCeilings)
	if err != nil {
		t.Fatal(err)
	}
	r := &KMSIssuerReconciler{
		Client: fc, Log: logf.Log, Recorder: record.NewFakeRecorder(10),
		KMSCA: &kmsca.KMSCA{Client: failingKMS{mock}}, Access: access, Clock: fakeclock.NewFakeClock(unitNow.Add(time.Hour)),
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
		t.Error("the issuer was marked not ready while its CA certificate is valid")
	}
}
