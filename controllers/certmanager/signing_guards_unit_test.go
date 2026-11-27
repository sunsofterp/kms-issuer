package certmanager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	fakeclock "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
)

// withAPI gives the reconciler an uncached reader: a second client holding the
// stored issuer and request as change leaves them (it returns what to store, so
// leaving one out means it was deleted). The reconciler's cached client is left as
// it was: a cache lagging the API server.
func (h *requestHarness) withAPI(t *testing.T, change func(issuer *kmsiapi.KMSIssuer, cr *cmapi.CertificateRequest) []client.Object) {
	t.Helper()
	issuer := &kmsiapi.KMSIssuer{}
	if err := h.fc.Get(context.TODO(), client.ObjectKeyFromObject(h.issuer), issuer); err != nil {
		t.Fatal(err)
	}
	cr := h.request(t)
	objs := change(issuer, cr)
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kmsiapi.AddToScheme(scheme)
	_ = cmapi.AddToScheme(scheme)
	h.r.APIReader = fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(objs...).Build()
}

// readyCondition is the request's Ready condition, or nil.
func readyCondition(cr *cmapi.CertificateRequest) *cmapi.CertificateRequestCondition {
	for i := range cr.Status.Conditions {
		if cr.Status.Conditions[i].Type == cmapi.CertificateRequestConditionReady {
			return &cr.Status.Conditions[i]
		}
	}
	return nil
}

// events drains the events the fake recorder holds.
func (h *requestHarness) events() []string {
	rec := h.r.Recorder.(*events.FakeRecorder)
	var got []string
	for {
		select {
		case e := <-rec.Events:
			got = append(got, e)
		default:
			return got
		}
	}
}

// expectPending checks a pass that must sign nothing and leave the request
// pending, with a warning event of eventReason.
func (h *requestHarness) expectPending(t *testing.T, name, eventReason string) {
	t.Helper()
	if err := h.reconcile(); err == nil {
		t.Errorf("%s: no error, want the request retried", name)
	}
	if n := h.kms.count(h.u.issuingKey); n != 0 {
		t.Errorf("%s: signed %d times", name, n)
	}
	cr := h.request(t)
	if ready := readyCondition(cr); ready == nil || ready.Status != cmmeta.ConditionFalse || ready.Reason != cmapi.CertificateRequestReasonPending {
		t.Errorf("%s: Ready condition %+v, want False/Pending", name, ready)
	}
	if len(cr.Status.Certificate) != 0 {
		t.Errorf("%s: a certificate was recorded", name)
	}
	found := false
	for _, e := range h.events() {
		found = found || strings.HasPrefix(e, "Warning "+eventReason+" ")
	}
	if !found {
		t.Errorf("%s: no Warning %s event", name, eventReason)
	}
}

// The issuer is verified from its spec when a request is signed: an issuer whose
// status says Ready, but which may no longer sign, signs nothing.
func TestSigningNeedsAVerifiedIssuer(t *testing.T) {
	t.Run("key no longer allowed", func(t *testing.T) {
		h := newRequestHarness(t, unitNow.Add(time.Hour))
		var err error
		if h.r.Access, err = NewAccess([]string{testNamespace}, []string{testKeyID}, unitCeilings(), []*x509.Certificate{h.u.root}, unitNow); err != nil {
			t.Fatal(err)
		}
		h.expectPending(t, "key no longer allowed", eventIssuerCannotSign)
	})
	t.Run("intermediate longer than the operator's maximum", func(t *testing.T) {
		h := newRequestHarness(t, unitNow.Add(time.Hour))
		// The unit intermediate is valid for 90 days; the operator now allows 60.
		c := unitCeilings()
		c.MaxIntermediateDuration = 60 * 24 * time.Hour
		c.MaxCertificateDuration = 24 * time.Hour
		var err error
		if h.r.Access, err = NewAccess([]string{testNamespace}, []string{h.u.issuingKey}, c, []*x509.Certificate{h.u.root}, unitNow); err != nil {
			t.Fatal(err)
		}
		h.updateIssuer(t, func(i *kmsiapi.KMSIssuer) { i.Spec.MaxCertificateDuration = &metav1.Duration{Duration: 24 * time.Hour} })
		h.expectPending(t, "intermediate too long", eventIssuerCannotSign)
		if msg := readyCondition(h.request(t)).Message; !strings.Contains(msg, "longer than the 1440h0m0s an intermediate may be") {
			t.Errorf("refused for %q, want the operator's intermediate maximum", msg)
		}
	})
	t.Run("intermediate expired", func(t *testing.T) {
		h := newRequestHarness(t, unitNow.Add(time.Hour))
		h.r.Clock.(*fakeclock.FakeClock).SetTime(h.u.intermediate.NotAfter.Add(time.Minute))
		h.expectPending(t, "intermediate expired", eventIssuerCannotSign)
	})
	t.Run("status not Ready", func(t *testing.T) {
		h := newRequestHarness(t, unitNow.Add(time.Hour))
		issuer := &kmsiapi.KMSIssuer{}
		if err := h.fc.Get(context.TODO(), client.ObjectKeyFromObject(h.issuer), issuer); err != nil {
			t.Fatal(err)
		}
		issuer.Status.Conditions = nil
		if err := h.fc.Status().Update(context.TODO(), issuer); err != nil {
			t.Fatal(err)
		}
		h.expectPending(t, "issuer not Ready", eventIssuerNotReady)
	})
}

// The issuer is read uncached: one just deleted never signs again from a stale
// cached copy.
func TestIssuerReadUncached(t *testing.T) {
	h := newRequestHarness(t, unitNow.Add(time.Hour))
	h.withAPI(t, func(_ *kmsiapi.KMSIssuer, cr *cmapi.CertificateRequest) []client.Object { return []client.Object{cr} })
	h.expectPending(t, "issuer deleted", eventIssuerUnavailable)
}

// The request is read uncached just before signing: if it already has a
// certificate, or changed since the cached copy, nothing is signed and it is
// retried (through the rate limiter).
func TestFreshRequestGuards(t *testing.T) {
	for name, change := range map[string]func(*cmapi.CertificateRequest){
		"already signed": func(cr *cmapi.CertificateRequest) { cr.Status.Certificate = []byte("signed elsewhere") }, // same resource version
		"changed":        func(cr *cmapi.CertificateRequest) { cr.ResourceVersion += "1" },
	} {
		h := newRequestHarness(t, unitNow.Add(time.Hour))
		h.withAPI(t, func(issuer *kmsiapi.KMSIssuer, cr *cmapi.CertificateRequest) []client.Object {
			change(cr)
			return []client.Object{issuer, cr}
		})
		err := h.reconcile()
		if err == nil || !strings.Contains(err.Error(), "cache is behind") {
			t.Errorf("%s: %v, want a retry because the cache is behind", name, err)
		}
		if n := h.kms.count(h.u.issuingKey); n != 0 {
			t.Errorf("%s: signed %d times", name, n)
		}
	}

	// Unchanged, it is signed (the guard isn't refusing everything).
	h := newRequestHarness(t, unitNow.Add(time.Hour))
	h.withAPI(t, func(issuer *kmsiapi.KMSIssuer, cr *cmapi.CertificateRequest) []client.Object {
		return []client.Object{issuer, cr}
	})
	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	if n := h.kms.count(h.u.issuingKey); n != 1 {
		t.Errorf("an unchanged request: signed %d times, want once", n)
	}
}

// A kept certificate goes only to the request it was signed for: a request
// recreated under the same name (another UID) gets its own.
func TestKeptCertificateNotForAnotherRequest(t *testing.T) {
	h := newRequestHarness(t, unitNow.Add(time.Hour))
	h.failNext = func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
		return errors.New("injected: status write failed")
	}
	if err := h.reconcile(); err == nil {
		t.Fatal("the failed write was not reported")
	}
	kept, ok := h.r.signed.Load(h.key)
	if !ok {
		t.Fatal("nothing kept after the failed write")
	}
	cr := h.request(t)
	cr.UID = "uid-2"
	if err := h.fc.Update(context.TODO(), cr); err != nil {
		t.Fatal(err)
	}
	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	if n := h.kms.count(h.u.issuingKey); n != 2 {
		t.Errorf("signed %d times, want a new certificate for the new request", n)
	}
	chain, err := kmsca.ParseCertificatesPEM(h.request(t).Status.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if chain[0].SerialNumber.Text(16) == kept.(signedCertificate).serial {
		t.Error("the other request's kept certificate was handed out")
	}
}

// A refusal longer than an event may be keeps its event, with the note cut short;
// the condition keeps the full message.
func TestLongRefusalKeepsItsEvent(t *testing.T) {
	h := newRequestHarness(t, unitNow.Add(time.Hour))
	long, err := newCertificateRequest("cr", "i", &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: strings.Repeat("a", 2000) + ".example.internal"}, DNSNames: []string{testHost},
	})
	if err != nil {
		t.Fatal(err)
	}
	cr := h.request(t)
	cr.Spec.Request = long.Spec.Request
	if err = h.fc.Update(context.TODO(), cr); err != nil {
		t.Fatal(err)
	}
	// A refusal is final: failed and not retried.
	if err = h.reconcile(); err != nil {
		t.Errorf("a refused request was retried: %v", err)
	}
	ready := readyCondition(h.request(t))
	if ready == nil || ready.Reason != cmapi.CertificateRequestReasonFailed || len(ready.Message) <= maxEventNote {
		t.Fatalf("Ready condition %+v, want Failed with the full message", ready)
	}
	got := h.events()
	if len(got) != 1 || !strings.HasPrefix(got[0], "Warning Failed ") {
		t.Fatalf("events %q, want one Failed warning", got)
	}
	note := strings.TrimPrefix(got[0], "Warning Failed ")
	if len(note) > maxEventNote || !strings.HasSuffix(note, "...") || !strings.HasPrefix(ready.Message, strings.TrimSuffix(note, "...")) {
		t.Errorf("note of %d bytes, want the message cut to at most %d ending in ...", len(note), maxEventNote)
	}
}

func TestEventNote(t *testing.T) {
	if s := strings.Repeat("x", maxEventNote); eventNote(s) != s {
		t.Error("a note of exactly the limit was changed")
	}
	// Multi-byte characters across the cut: never split one.
	n := eventNote(strings.Repeat("é", maxEventNote))
	if len(n) > maxEventNote || !strings.HasSuffix(n, "...") || strings.ContainsRune(n, '�') || !strings.HasPrefix(n, "éé") {
		t.Errorf("cut note: %d bytes, %q...", len(n), n[:8])
	}
	for i := 0; i < len(n)-3; i += 2 {
		if n[i:i+2] != "é" {
			t.Fatalf("character split at byte %d", i)
		}
	}
}

// Each refusal of NewAccess.
func TestNewAccessRefusals(t *testing.T) {
	u := newUnitCA(t)
	const wantAlias = "is an alias"
	roots := []*x509.Certificate{u.root}
	with := func(change func(*Ceilings)) Ceilings {
		c := unitCeilings()
		change(&c)
		return c
	}
	for _, c := range []struct {
		name       string
		namespaces []string
		keys       []string
		ceilings   Ceilings
		roots      []*x509.Certificate
		want       string
	}{
		{"an alias as a key", []string{testNamespace}, []string{rootAlias}, unitCeilings(), roots, wantAlias},
		{"an alias ARN as a key", []string{testNamespace}, []string{"arn:aws:kms:eu-west-1:111122223333:alias/x"}, unitCeilings(), roots, wantAlias},
		{"no namespace", []string{" "}, []string{u.issuingKey}, unitCeilings(), roots, "namespace is required"},
		{"no key", []string{testNamespace}, []string{""}, unitCeilings(), roots, "KMS key is required"},
		{"no domain", []string{testNamespace}, []string{u.issuingKey}, with(func(c *Ceilings) { c.PermittedDNSDomains = nil }), roots, "permitted DNS domain is required"},
		{"leaf maximum under 1h", []string{testNamespace}, []string{u.issuingKey}, with(func(c *Ceilings) { c.MaxCertificateDuration = 59 * time.Minute }), roots, "at least 1h"},
		{"leaf maximum not whole seconds", []string{testNamespace}, []string{u.issuingKey},
			with(func(c *Ceilings) { c.MaxCertificateDuration = 2*time.Hour + time.Millisecond }), roots, "whole seconds"},
		{"no roots", []string{testNamespace}, []string{u.issuingKey}, unitCeilings(), nil, "at least one root certificate is required"},
	} {
		_, err := NewAccess(c.namespaces, c.keys, c.ceilings, c.roots, unitNow)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// What NewAccess accepts is what it keeps.
func TestNewAccessKeepsTheCeilings(t *testing.T) {
	u := newUnitCA(t)
	c := unitCeilings()
	c.AllowWildcards = true
	c.MaxIntermediateDuration = 60 * 24 * time.Hour
	c.MaxCertificateDuration = 24 * time.Hour
	a, err := NewAccess([]string{testNamespace}, []string{u.issuingKey}, c, []*x509.Certificate{u.root}, unitNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.MaxIntermediateDuration(); got != c.MaxIntermediateDuration {
		t.Errorf("intermediate maximum %s, want %s", got, c.MaxIntermediateDuration)
	}
	issuer := &kmsiapi.KMSIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace},
		Spec:       kmsiapi.KMSIssuerSpec{KeyID: u.issuingKey, PermittedDNSDomains: []string{testDomain}, AllowWildcards: true},
	}
	if err := a.CheckIssuer(issuer, settings{maxCertificateDuration: 24 * time.Hour}); err != nil {
		t.Errorf("an issuer within the ceilings, wildcards allowed: %v", err)
	}
	if err := a.CheckIssuer(issuer, settings{maxCertificateDuration: 25 * time.Hour}); err == nil {
		t.Error("an issuer over the leaf maximum was accepted")
	}
}
