package certmanager

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	fakeclock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	mocks "github.com/sunsofterp/kms-issuer/v5/pkg/kmsmock"
)

// staleCache is a client whose reads of obj's kind return stale (a cache that
// hasn't caught up with the controller's last status write) and whose writes go to
// the API server.
type staleCache struct {
	client.Client
	stale client.Object
}

func (s staleCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	switch o := obj.(type) {
	case *kmsiapi.KMSIssuer:
		if stale, ok := s.stale.(*kmsiapi.KMSIssuer); ok {
			stale.DeepCopyInto(o)
			return nil
		}
	case *kmsiapi.KMSKey:
		if stale, ok := s.stale.(*kmsiapi.KMSKey); ok {
			stale.DeepCopyInto(o)
			return nil
		}
	}
	return s.Client.Get(ctx, key, obj, opts...)
}

const staleAlias = "alias/stale"

func newScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kmsiapi.AddToScheme(scheme)
	return scheme
}

// An issuer the last pass marked not Ready, whose spec is good again, is made
// Ready even when the cache still holds the Ready status from before that write:
// the controller ignores its own status writes, so nothing else would repair it.
func TestIssuerReadyDespiteStaleCache(t *testing.T) {
	u := newUnitCA(t)
	issuer := &kmsiapi.KMSIssuer{}
	issuer.Namespace, issuer.Name = testNamespace, "i"
	issuer.Spec = kmsiapi.KMSIssuerSpec{
		KeyID: u.issuingKey, IntermediateCertificate: string(encodeForTest(u.intermediate.Raw)), PermittedDNSDomains: []string{testDomain},
	}
	notReady := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionFalse, kmsiapi.KMSIssuerReasonFailed, "an earlier spec was refused")
	issuer.Status.SetCondition(&notReady)
	issuer.Status.Certificate = encodeForTest(u.intermediate.Raw)
	api := fakeclient.NewClientBuilder().WithScheme(newScheme()).WithObjects(issuer).WithStatusSubresource(issuer).Build()

	stale := issuer.DeepCopy()
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, kmsiapi.KMSIssuerReasonIssued, "")
	stale.Status.SetCondition(&ready)
	access, err := NewAccess([]string{testNamespace}, []string{u.issuingKey}, testCeilings, []*x509.Certificate{u.root}, unitNow)
	if err != nil {
		t.Fatal(err)
	}
	r := &KMSIssuerReconciler{
		Client: staleCache{Client: api, stale: stale}, APIReader: api, Log: logf.Log, Recorder: events.NewFakeRecorder(10),
		KMSCA: &kmsca.KMSCA{Client: u.mock}, Access: access, Clock: fakeclock.NewFakeClock(unitNow.Add(time.Hour)),
	}
	if _, err := r.Reconcile(context.TODO(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(issuer)}); err != nil {
		t.Fatal(err)
	}
	got := &kmsiapi.KMSIssuer{}
	if err := api.Get(context.TODO(), client.ObjectKeyFromObject(issuer), got); err != nil {
		t.Fatal(err)
	}
	if !got.Status.IsReady() {
		t.Errorf("the issuer was left not Ready: %+v", got.Status.Conditions)
	}
}

// The same for a KMSKey: a success after a failure is written even when the cache
// still holds the Ready status from before the failure was written.
func TestKMSKeyReadyDespiteStaleCache(t *testing.T) {
	ca := &kmsca.KMSCA{Client: mocks.New()}
	kmsKey := &kmsiapi.KMSKey{}
	kmsKey.Namespace, kmsKey.Name, kmsKey.UID = testNamespace, "k", kmsKeyUID
	kmsKey.Finalizers = []string{FinalizerName}
	kmsKey.Spec = kmsiapi.KMSKeySpec{AliasName: staleAlias, DeletionPolicy: retain}
	keyID, err := ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: kmsKey.Spec.AliasName, OwnerUID: string(kmsKey.UID)})
	if err != nil {
		t.Fatal(err)
	}
	kmsKey.Status.KeyID = keyID
	failed := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionFalse, kmsiapi.KMSKeyReasonFailed, "an earlier attempt failed")
	kmsKey.Status.SetCondition(&failed)
	api := fakeclient.NewClientBuilder().WithScheme(newScheme()).WithObjects(kmsKey).WithStatusSubresource(kmsKey).Build()

	stale := kmsKey.DeepCopy()
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, kmsiapi.KMSKeyReasonIssued, "")
	stale.Status.SetCondition(&ready)
	r := &KMSKeyReconciler{
		Client: staleCache{Client: api, stale: stale}, APIReader: api, Log: logf.Log, Scheme: newScheme(), Recorder: events.NewFakeRecorder(10), KMSCA: ca,
	}
	if _, err := r.Reconcile(context.TODO(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(kmsKey)}); err != nil {
		t.Fatal(err)
	}
	got := &kmsiapi.KMSKey{}
	if err := api.Get(context.TODO(), client.ObjectKeyFromObject(kmsKey), got); err != nil {
		t.Fatal(err)
	}
	if !got.Status.IsReady() {
		t.Errorf("the KMSKey was left not Ready: %+v", got.Status.Conditions)
	}
}

// A failing KMSKey pass keeps the key ID even when the cache still holds a copy
// from before the ID was written: the status written is the live object's.
func TestKMSKeyFailureKeepsKeyIDDespiteStaleCache(t *testing.T) {
	mock := mocks.New()
	kmsKey := &kmsiapi.KMSKey{}
	kmsKey.Namespace, kmsKey.Name, kmsKey.UID = testNamespace, "k", kmsKeyUID
	kmsKey.Finalizers = []string{FinalizerName}
	kmsKey.Spec = kmsiapi.KMSKeySpec{AliasName: staleAlias, DeletionPolicy: retain}
	keyID, err := (&kmsca.KMSCA{Client: mock}).CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: kmsKey.Spec.AliasName, OwnerUID: string(kmsKey.UID)})
	if err != nil {
		t.Fatal(err)
	}
	stale := kmsKey.DeepCopy()
	kmsKey.Status.KeyID = keyID
	api := fakeclient.NewClientBuilder().WithScheme(newScheme()).WithObjects(kmsKey).WithStatusSubresource(kmsKey).Build()
	r := &KMSKeyReconciler{
		Client: staleCache{Client: api, stale: stale}, APIReader: api, Log: logf.Log, Scheme: newScheme(), Recorder: events.NewFakeRecorder(10),
		KMSCA: &kmsca.KMSCA{Client: &deniedKMS{KMSMock: mock, describe: true}},
	}
	if _, err := r.Reconcile(context.TODO(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(kmsKey)}); err == nil {
		t.Fatal("a refused DescribeKey was swallowed")
	}
	got := &kmsiapi.KMSKey{}
	if err := api.Get(context.TODO(), client.ObjectKeyFromObject(kmsKey), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.KeyID != keyID || got.Status.IsReady() {
		t.Errorf("status %+v, want not Ready with key ID %q kept", got.Status, keyID)
	}
}
