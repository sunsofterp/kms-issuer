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
	root, _ := makeRootKey(t, u, alias, name, notBefore, d)
	return root
}

// makeRootKey is makeRoot, also returning the new root's key.
func makeRootKey(t *testing.T, u *unitCA, alias, name string, notBefore time.Time, d time.Duration) (*x509.Certificate, string) {
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
	return root, key
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

// An expired root left in the pin during a root replacement, or a new one not valid
// yet, is reported, not fatal; with no valid root, startup fails. Structural
// faults stay fatal.
func TestNewAccessRoots(t *testing.T) {
	u := newUnitCA(t)
	old := makeRoot(t, u, "alias/old-root", "Old Root", unitNow.Add(-2*365*24*time.Hour), 365*24*time.Hour)
	future := makeRoot(t, u, "alias/future-root", "Future Root", unitNow.Add(24*time.Hour), 365*24*time.Hour)

	a, err := NewAccess([]string{"default"}, []string{u.issuingKey}, unitCeilings(), []*x509.Certificate{old, u.root, future}, unitNow)
	if err != nil {
		t.Fatalf("an expired and a not-yet-valid root beside a valid one: %v", err)
	}
	if now := a.RootsAt(unitNow); len(now) != 1 || !now[0].Equal(u.root) {
		t.Errorf("roots valid now: %d, want only the current one", len(now))
	}
	if later := a.RootsAt(unitNow.Add(48 * time.Hour)); len(later) != 2 {
		t.Errorf("roots valid once the new one starts: %d, want 2", len(later))
	}
	if s := a.Skipped(); len(s) != 2 || s[0].Index != 1 || !s[0].Expired || s[1].Index != 3 || s[1].Expired {
		t.Errorf("skipped: %+v, want root 1 expired and root 3 not yet valid", s)
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

// At signing time an intermediate chains only to a root valid then: never to an
// expired one, and to a new one from its notBefore with no new Access (no
// restart). An expired root's key is still refused as an issuing key.
func TestIntermediatesUnderSkippedRoots(t *testing.T) {
	u := newUnitCA(t)
	old, oldKey := makeRootKey(t, u, "alias/old-root", "Old Root", unitNow.Add(-365*24*time.Hour), 365*24*time.Hour+time.Hour)
	future, futureKey := makeRootKey(t, u, "alias/future-root", "Future Root", unitNow.Add(24*time.Hour), 365*24*time.Hour)
	in := func(name string, from time.Time) *kmsca.CAInput {
		return &kmsca.CAInput{Subject: pkix.Name{CommonName: name}, PermittedDNSDomains: []string{"example.internal"}, Duration: 48 * time.Hour, Now: from}
	}
	// Hand-signed under the old root, outliving it (kms-ca refuses to make this),
	// so that only the root's expiry can refuse it.
	tmpl, err := kmsca.CATemplate(in("Under Old", unitNow.Add(-time.Hour)), kmsca.Intermediate)
	if err != nil {
		t.Fatal(err)
	}
	issuingPub, err := u.ca.PublicKey(context.TODO(), u.issuingKey)
	if err != nil {
		t.Fatal(err)
	}
	underOld, err := u.ca.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{KeyID: oldKey, Cert: tmpl, Parent: old, PublicKey: issuingPub})
	if err != nil {
		t.Fatal(err)
	}
	if !underOld.NotAfter.After(old.NotAfter.Add(time.Minute)) {
		t.Fatal("test setup: the intermediate must outlive the old root")
	}
	underFuture, err := u.ca.MakeIntermediate(context.TODO(), futureKey, future, u.issuingKey, in("Under Future", unitNow.Add(25*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAccess([]string{"default"}, []string{u.issuingKey, oldKey}, unitCeilings(), []*x509.Certificate{old, u.root, future}, unitNow)
	if err != nil {
		t.Fatal(err)
	}
	issuer := func(keyID string, inter *x509.Certificate) *kmsiapi.KMSIssuer {
		return &kmsiapi.KMSIssuer{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "i"},
			Spec: kmsiapi.KMSIssuerSpec{KeyID: keyID, IntermediateCertificate: string(encodeForTest(inter.Raw)),
				PermittedDNSDomains: []string{"example.internal"}},
		}
	}
	afterOldExpired := old.NotAfter.Add(time.Minute)
	// Refused by the pinned-root check itself (RootsAt), not only later by path
	// validation: the error names the root as not pinned.
	if _, err := verifyIssuer(context.TODO(), u.ca, a, issuer(u.issuingKey, underOld), afterOldExpired); err == nil ||
		!strings.Contains(err.Error(), "not issued by a pinned root") {
		t.Errorf("an intermediate under an expired root: %v, want refused as not issued by a pinned root", err)
	}
	if _, err := verifyIssuer(context.TODO(), u.ca, a, issuer(u.issuingKey, underFuture), unitNow.Add(25*time.Hour+time.Minute)); err != nil {
		t.Errorf("an intermediate under a root that became valid after startup: %v", err)
	}
	if _, err := verifyIssuer(context.TODO(), u.ca, a, issuer(u.issuingKey, underFuture), unitNow.Add(time.Hour)); err == nil ||
		!strings.Contains(err.Error(), "not issued by a pinned root") {
		t.Errorf("an intermediate under a root not valid yet: %v, want refused as not issued by a pinned root", err)
	}

	// The expired old root's key as an issuing key, under the current root.
	onOldKey, err := u.ca.MakeIntermediate(context.TODO(), u.rootKey, u.root, oldKey, in("On Old Root Key", unitNow))
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyIssuer(context.TODO(), u.ca, a, issuer(oldKey, onOldKey), afterOldExpired)
	if err == nil || !strings.Contains(err.Error(), "root key") {
		t.Errorf("an expired root's key as the issuing key: %v", err)
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
	c.MaxCertificateDuration = 1401600 * time.Hour // doubled, this overflows
	if _, err := NewAccess([]string{"default"}, []string{u.issuingKey}, c, roots, unitNow); err == nil {
		t.Error("a leaf maximum that overflows when doubled accepted")
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

// A kept certificate the issuer would no longer sign (narrowed before the retry)
// is dropped and a new one signed under the issuer as it is now.
func TestKeptCertificateDroppedWhenIssuerNarrowed(t *testing.T) {
	h := newRequestHarness(t, unitNow.Add(time.Hour))
	h.failNext = func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
		return errors.New("injected: status write failed")
	}
	if err := h.reconcile(); err == nil {
		t.Fatal("the failed write was not reported")
	}
	issuer := &kmsiapi.KMSIssuer{}
	if err := h.fc.Get(context.TODO(), client.ObjectKeyFromObject(h.issuer), issuer); err != nil {
		t.Fatal(err)
	}
	issuer.Spec.MaxCertificateDuration = &metav1.Duration{Duration: 12 * time.Hour} // the kept leaf is 24h
	if err := h.fc.Update(context.TODO(), issuer); err != nil {
		t.Fatal(err)
	}
	// The request still asks for 24h, which the narrowed issuer refuses: it fails,
	// and the kept 24h certificate is never handed out.
	_ = h.reconcile()
	if n := h.kms.count(h.u.issuingKey); n != 1 {
		t.Errorf("signed %d times, want once", n)
	}
	if cr := h.request(t); len(cr.Status.Certificate) != 0 {
		t.Error("the kept certificate was recorded after the issuer was narrowed")
	}
	if h.kept() {
		t.Error("the unacceptable certificate is still kept")
	}
}

// A kept certificate is dropped if the issuer now uses another key (recreated
// under the same name): it is re-signed with the new key, never handed out beside
// the old key's intermediate.
func TestKeptCertificateDroppedOnKeyChange(t *testing.T) {
	h := newRequestHarness(t, unitNow.Add(time.Hour))
	h.failNext = func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
		return errors.New("injected: status write failed")
	}
	if err := h.reconcile(); err == nil {
		t.Fatal("the failed write was not reported")
	}
	keyB, err := h.u.ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/issuing-b", OwnerUID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	interB, err := h.u.ca.MakeIntermediate(context.TODO(), h.u.rootKey, h.u.root, keyB, &kmsca.CAInput{
		Subject: pkix.Name{CommonName: "Issuing B"}, PermittedDNSDomains: []string{"example.internal"}, Duration: 90 * 24 * time.Hour, Now: unitNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.r.Access, err = NewAccess([]string{"default"}, []string{h.u.issuingKey, keyB}, unitCeilings(), []*x509.Certificate{h.u.root}, unitNow); err != nil {
		t.Fatal(err)
	}
	issuer := &kmsiapi.KMSIssuer{}
	if err := h.fc.Get(context.TODO(), client.ObjectKeyFromObject(h.issuer), issuer); err != nil {
		t.Fatal(err)
	}
	issuer.Spec.KeyID = keyB
	issuer.Spec.IntermediateCertificate = string(encodeForTest(interB.Raw))
	if err := h.fc.Update(context.TODO(), issuer); err != nil {
		t.Fatal(err)
	}
	if err := h.reconcile(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if a, b := h.kms.count(h.u.issuingKey), h.kms.count(keyB); a != 1 || b != 1 {
		t.Errorf("signed %d times with the old key and %d with the new, want once each", a, b)
	}
	chain, err := kmsca.ParseCertificatesPEM(h.request(t).Status.Certificate)
	if err != nil || len(chain) != 2 {
		t.Fatalf("chain: %d certificates, %v", len(chain), err)
	}
	if chain[1].Subject.CommonName != "Issuing B" || chain[0].CheckSignatureFrom(chain[1]) != nil {
		t.Errorf("recorded beside %q; want a leaf signed by the new key beside its intermediate", chain[1].Subject.CommonName)
	}
}

func TestStillAcceptable(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"svc.example.internal"}, NotBefore: unitNow, NotAfter: unitNow.Add(24 * time.Hour)}
	wild := &x509.Certificate{DNSNames: []string{"*.example.internal"}, NotBefore: unitNow, NotAfter: unitNow.Add(24 * time.Hour)}
	issuer := func(domains []string, wildcards bool) *kmsiapi.KMSIssuer {
		return &kmsiapi.KMSIssuer{Spec: kmsiapi.KMSIssuerSpec{PermittedDNSDomains: domains, AllowWildcards: wildcards}}
	}
	day := settings{maxCertificateDuration: 24 * time.Hour}
	if why := stillAcceptable(leaf, issuer([]string{"example.internal"}, false), day, unitNow.Add(time.Hour)); why != "" {
		t.Errorf("acceptable leaf refused: %s", why)
	}
	for name, why := range map[string]string{
		"under an hour left": stillAcceptable(leaf, issuer([]string{"example.internal"}, false), day, unitNow.Add(23*time.Hour+time.Minute)),
		"longer than now":    stillAcceptable(leaf, issuer([]string{"example.internal"}, false), settings{maxCertificateDuration: 12 * time.Hour}, unitNow),
		"a name now outside": stillAcceptable(leaf, issuer([]string{"other.internal"}, false), day, unitNow),
		"wildcards now off":  stillAcceptable(wild, issuer([]string{"example.internal"}, false), day, unitNow),
	} {
		if why == "" {
			t.Errorf("%s: accepted", name)
		}
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
