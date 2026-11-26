package certmanager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	fakeclock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	mocks "github.com/sunsofterp/kms-issuer/v5/pkg/kmsmock"
)

// countingKMS counts Sign calls per key.
type countingKMS struct {
	*mocks.KMSMock
	mu    sync.Mutex
	signs map[string]int
}

func (c *countingKMS) Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
	c.mu.Lock()
	c.signs[aws.ToString(in.KeyId)]++
	c.mu.Unlock()
	return c.KMSMock.Sign(ctx, in, opts...)
}

func (c *countingKMS) count(keyID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signs[keyID]
}

func unitCeilings(domains ...string) Ceilings {
	if len(domains) == 0 {
		domains = []string{"example.internal"}
	}
	return Ceilings{PermittedDNSDomains: domains, MaxCertificateDuration: 30 * 24 * time.Hour, MaxIntermediateDuration: kmsca.MaxIntermediateDuration}
}

// makeRoot makes another root on a new key, valid from notBefore for d.
func makeRoot(t *testing.T, u *unitCA, alias, name string, notBefore time.Time, d time.Duration) *x509.Certificate {
	t.Helper()
	key, err := u.ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: alias, OwnerUID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	root, err := u.ca.MakeRoot(context.TODO(), key, &kmsca.CAInput{
		Subject: pkix.Name{CommonName: name}, PermittedDNSDomains: []string{"example.internal"}, Duration: d, Now: notBefore,
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// selfSign signs a root template, after mutate, with the unit CA's root key.
func selfSign(t *testing.T, u *unitCA, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	tmpl, err := kmsca.CATemplate(&kmsca.CAInput{
		Subject: pkix.Name{CommonName: "Odd Root"}, PermittedDNSDomains: []string{"example.internal"}, Duration: 365 * 24 * time.Hour, Now: unitNow,
	}, kmsca.Root)
	if err != nil {
		t.Fatal(err)
	}
	mutate(tmpl)
	pub, err := u.ca.PublicKey(context.TODO(), u.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.PublicKey = pub // self-signed: the parent is the template
	cert, err := u.ca.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{KeyID: u.rootKey, Cert: tmpl, Parent: tmpl, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// An expired root left in the pin during a root replacement is skipped, not
// fatal; with no valid root left, startup fails. Structural faults stay fatal.
func TestNewAccessRoots(t *testing.T) {
	u := newUnitCA(t)
	old := makeRoot(t, u, "alias/old-root", "Old Root", unitNow.Add(-2*365*24*time.Hour), 365*24*time.Hour)
	future := makeRoot(t, u, "alias/future-root", "Future Root", unitNow.Add(24*time.Hour), 365*24*time.Hour)

	a, err := NewAccess([]string{"default"}, []string{u.issuingKey}, unitCeilings(), []*x509.Certificate{old, u.root, future}, unitNow)
	if err != nil {
		t.Fatalf("an expired and a not-yet-valid root beside a valid one: %v", err)
	}
	if len(a.Roots()) != 1 || !a.Roots()[0].Equal(u.root) {
		t.Errorf("roots in use: %d, want only the valid one", len(a.Roots()))
	}
	if s := a.Skipped(); len(s) != 2 || s[0].Index != 1 || s[1].Index != 3 {
		t.Errorf("skipped: %+v, want roots 1 and 3", s)
	}

	if _, err := NewAccess([]string{"default"}, []string{u.issuingKey}, unitCeilings(), []*x509.Certificate{old}, unitNow); err == nil {
		t.Error("started with only an expired root")
	}

	wideURI := selfSign(t, u, func(c *x509.Certificate) { c.PermittedURIDomains = []string{".other.internal"} })
	if _, err := NewAccess([]string{"default"}, []string{u.issuingKey}, unitCeilings(), []*x509.Certificate{u.root, wideURI}, unitNow); err == nil {
		t.Error("a root whose URI constraint is outside the ceilings was accepted")
	}
	badEmail := selfSign(t, u, func(c *x509.Certificate) { c.PermittedEmailAddresses = []string{"Example.Internal"} })
	if err := kmsca.ValidateRootStructure(badEmail); err == nil {
		t.Error("a root with an invalid email constraint domain passed")
	}
	expiredAndWide := selfSign(t, u, func(c *x509.Certificate) {
		c.PermittedDNSDomains = []string{"other.internal"}
		c.NotAfter = unitNow.Add(-time.Hour)
		c.NotBefore = unitNow.Add(-2 * time.Hour)
	})
	if _, err := NewAccess([]string{"default"}, []string{u.issuingKey}, unitCeilings(), []*x509.Certificate{u.root, expiredAndWide}, unitNow); err == nil {
		t.Error("an expired root outside the ceilings was skipped instead of refused")
	}
}

// Permitted domains and the duration ceilings are checked at startup.
func TestNewAccessCeilings(t *testing.T) {
	u := newUnitCA(t)
	roots := []*x509.Certificate{u.root}
	for _, d := range []string{"Example.internal", ".example.internal", "*.example.internal", "example.internal.", "internal", ""} {
		if _, err := NewAccess([]string{"default"}, []string{u.issuingKey}, unitCeilings(d), roots, unitNow); err == nil {
			t.Errorf("permitted domain %q accepted", d)
		}
	}
	for _, d := range []time.Duration{0, -time.Hour, kmsca.MaxIntermediateDuration + time.Second} {
		c := unitCeilings()
		c.MaxIntermediateDuration = d
		if _, err := NewAccess([]string{"default"}, []string{u.issuingKey}, c, roots, unitNow); err == nil {
			t.Errorf("maximum intermediate duration %s accepted", d)
		}
	}
	c := unitCeilings()
	c.MaxCertificateDuration = kmsca.MaxIntermediateDuration / 2
	if _, err := NewAccess([]string{"default"}, []string{u.issuingKey}, c, roots, unitNow); err == nil {
		t.Error("a leaf maximum of half the intermediate maximum accepted")
	}
	c.MaxCertificateDuration = kmsca.MaxIntermediateDuration/2 - time.Second
	if _, err := NewAccess([]string{"default"}, []string{u.issuingKey}, c, roots, unitNow); err != nil {
		t.Errorf("a leaf maximum just under half the intermediate maximum: %v", err)
	}
}

// requestHarness is one approved request for a ready issuer, with a fake client
// whose CertificateRequest status writes can be made to fail.
type requestHarness struct {
	u      *unitCA
	kms    *countingKMS
	fc     client.Client
	r      *CertificateRequestReconciler
	key    types.NamespacedName
	issuer *kmsiapi.KMSIssuer
	// failNext, if set, replaces the next CertificateRequest status write.
	failNext func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error
}

func newRequestHarness(t *testing.T, now time.Time) *requestHarness {
	t.Helper()
	h := &requestHarness{u: newUnitCA(t)}
	h.kms = &countingKMS{KMSMock: h.u.mock, signs: map[string]int{}}
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, kmsiapi.KMSIssuerReasonIssued, "")
	h.issuer = &kmsiapi.KMSIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "i"},
		Spec: kmsiapi.KMSIssuerSpec{
			KeyID: h.u.issuingKey, IntermediateCertificate: string(encodeForTest(h.u.intermediate.Raw)),
			PermittedDNSDomains: []string{"example.internal"},
		},
		Status: kmsiapi.KMSIssuerStatus{Status: kmsiapi.Status{Conditions: []kmsiapi.Condition{ready}}},
	}
	cr, err := newCertificateRequest("cr", "i", &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "svc.example.internal"}, DNSNames: []string{"svc.example.internal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cr.Namespace = "default"
	cr.UID = "uid-1"
	cr.Status.Conditions = []cmapi.CertificateRequestCondition{{Type: cmapi.CertificateRequestConditionApproved, Status: cmmeta.ConditionTrue, Reason: "test"}}
	h.key = types.NamespacedName{Namespace: "default", Name: "cr"}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kmsiapi.AddToScheme(scheme)
	_ = cmapi.AddToScheme(scheme)
	h.fc = fakeclient.NewClientBuilder().WithScheme(scheme).
		WithObjects(h.issuer, cr).WithStatusSubresource(h.issuer, cr).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if _, ok := obj.(*cmapi.CertificateRequest); ok && h.failNext != nil {
					f := h.failNext
					h.failNext = nil
					return f(ctx, c, sub, obj, opts...)
				}
				return c.SubResource(sub).Update(ctx, obj, opts...)
			},
		}).Build()
	access, err := NewAccess([]string{"default"}, []string{h.u.issuingKey}, unitCeilings(), []*x509.Certificate{h.u.root}, unitNow)
	if err != nil {
		t.Fatal(err)
	}
	h.r = &CertificateRequestReconciler{
		Client: h.fc, Log: logf.Log, Recorder: record.NewFakeRecorder(100),
		KMSCA: &kmsca.KMSCA{Client: h.kms}, Access: access, Clock: fakeclock.NewFakeClock(now),
	}
	return h
}

func (h *requestHarness) reconcile() error {
	_, err := h.r.Reconcile(context.TODO(), ctrl.Request{NamespacedName: h.key})
	return err
}

func (h *requestHarness) request(t *testing.T) *cmapi.CertificateRequest {
	t.Helper()
	cr := &cmapi.CertificateRequest{}
	if err := h.fc.Get(context.TODO(), h.key, cr); err != nil {
		t.Fatal(err)
	}
	return cr
}

func (h *requestHarness) kept() bool {
	_, ok := h.r.signed.Load(h.key)
	return ok
}

// A certificate whose recording failed is recorded on retry, never signed again,
// and beside the intermediate that signed it even if the issuer's intermediate was
// replaced in between.
func TestSignedOnceKeepsItsChain(t *testing.T) {
	h := newRequestHarness(t, unitNow.Add(time.Hour))
	h.failNext = func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
		return errors.New("injected: status write failed")
	}
	if err := h.reconcile(); err == nil {
		t.Fatal("the failed write was not reported")
	}
	if !h.kept() || h.kms.count(h.u.issuingKey) != 1 {
		t.Fatalf("after the failed write: kept %v, signed %d times", h.kept(), h.kms.count(h.u.issuingKey))
	}

	// The intermediate is renewed before the retry.
	renewed, err := h.u.ca.MakeIntermediate(context.TODO(), h.u.rootKey, h.u.root, h.u.issuingKey, &kmsca.CAInput{
		Subject: pkix.Name{CommonName: "Issuing 2027"}, PermittedDNSDomains: []string{"example.internal"}, Duration: 90 * 24 * time.Hour, Now: unitNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer := &kmsiapi.KMSIssuer{}
	if err := h.fc.Get(context.TODO(), client.ObjectKeyFromObject(h.issuer), issuer); err != nil {
		t.Fatal(err)
	}
	issuer.Spec.IntermediateCertificate = string(encodeForTest(renewed.Raw))
	if err := h.fc.Update(context.TODO(), issuer); err != nil {
		t.Fatal(err)
	}

	if err := h.reconcile(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := h.kms.count(h.u.issuingKey); n != 1 {
		t.Errorf("signed %d times, want once", n)
	}
	if h.kept() {
		t.Error("the recorded certificate is still kept")
	}
	cr := h.request(t)
	chain, err := kmsca.ParseCertificatesPEM(cr.Status.Certificate)
	if err != nil || len(chain) != 2 {
		t.Fatalf("chain: %d certificates, %v", len(chain), err)
	}
	if chain[1].Subject.CommonName != "Issuing" {
		t.Errorf("recorded beside %q, want the intermediate that signed it", chain[1].Subject.CommonName)
	}
	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Errorf("the leaf does not verify against the intermediate beside it: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(h.u.root)
	inter := x509.NewCertPool()
	inter.AddCert(chain[1])
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: unitNow.Add(2 * time.Hour)}); err != nil {
		t.Errorf("the chain handed out does not verify to the root: %v", err)
	}
}

// A write that succeeded but reported an error leaves nothing kept once the next
// pass sees the certificate.
func TestKeptCertificateDroppedOnceRecorded(t *testing.T) {
	h := newRequestHarness(t, unitNow.Add(time.Hour))
	h.failNext = func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
		if err := c.SubResource(sub).Update(ctx, obj, opts...); err != nil {
			return err
		}
		return errors.New("injected: write applied, error reported")
	}
	if err := h.reconcile(); err == nil {
		t.Fatal("the error was not reported")
	}
	if !h.kept() {
		t.Fatal("nothing kept after a reported failure")
	}
	if len(h.request(t).Status.Certificate) == 0 {
		t.Fatal("the write was not applied")
	}
	if err := h.reconcile(); err != nil {
		t.Fatal(err)
	}
	if h.kept() {
		t.Error("an entry for a finished request was left in the cache")
	}
	if n := h.kms.count(h.u.issuingKey); n != 1 {
		t.Errorf("signed %d times, want once", n)
	}
}

// Under an hour of intermediate left, the request waits with a Pending reason
// saying why, and is not failed.
func TestLastHourWaitsPending(t *testing.T) {
	h := newRequestHarness(t, unitNow)
	h.r.Clock.(*fakeclock.FakeClock).SetTime(h.u.intermediate.NotAfter.Add(-30 * time.Minute))
	if err := h.reconcile(); err == nil {
		t.Fatal("no retry")
	}
	if n := h.kms.count(h.u.issuingKey); n != 0 {
		t.Errorf("signed %d times", n)
	}
	var ready *cmapi.CertificateRequestCondition
	conditions := h.request(t).Status.Conditions
	for i := range conditions {
		if conditions[i].Type == cmapi.CertificateRequestConditionReady {
			ready = &conditions[i]
		}
	}
	if ready == nil || ready.Status != cmmeta.ConditionFalse || ready.Reason != cmapi.CertificateRequestReasonPending ||
		!strings.Contains(ready.Message, "renew the intermediate") {
		t.Errorf("Ready condition %+v, want False/Pending saying to renew the intermediate", ready)
	}
}
