package certmanager

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

const (
	accessDenied    = "AccessDeniedException"
	accessDeniedMsg = "User is not authorized to perform this operation"
	serviceKMS      = "KMS"
)

var requestIDs atomic.Int64

// awsError is an error as the AWS SDK returns it for a refused call: an operation
// error around a response error whose request ID is new on every call.
func awsError(operation string) error {
	return awsErrorSaying(operation, accessDeniedMsg)
}

func awsErrorSaying(operation, message string) error {
	return &smithy.OperationError{ServiceID: serviceKMS, OperationName: operation, Err: &awshttp.ResponseError{
		RequestID: fmt.Sprintf("req-%d", requestIDs.Add(1)),
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
			Err:      &smithy.GenericAPIError{Code: accessDenied, Message: message},
		},
	}}
}

// deniedKMS is the mock with GetPublicKey, Sign and CreateAlias refused as the
// SDK would refuse them, saying message (default accessDeniedMsg).
type deniedKMS struct {
	*mocks.KMSMock
	publicKey, sign, alias bool
	message                string
}

func (k *deniedKMS) denied(operation string) error {
	if k.message != "" {
		return awsErrorSaying(operation, k.message)
	}
	return awsError(operation)
}

func (k *deniedKMS) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if k.publicKey {
		return nil, k.denied("GetPublicKey")
	}
	return k.KMSMock.GetPublicKey(ctx, in, opts...)
}

func (k *deniedKMS) Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
	if k.sign {
		return nil, k.denied("Sign")
	}
	return k.KMSMock.Sign(ctx, in, opts...)
}

func (k *deniedKMS) CreateAlias(ctx context.Context, in *kms.CreateAliasInput, opts ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	if k.alias {
		return nil, k.denied("CreateAlias")
	}
	return k.KMSMock.CreateAlias(ctx, in, opts...)
}

// expectNotesCut checks every event rec holds has a note of at most maxEventNote
// bytes and no request ID, and that there is at least one.
func expectNotesCut(t *testing.T, name string, rec *events.FakeRecorder) {
	t.Helper()
	n := 0
	for {
		select {
		case e := <-rec.Events:
			n++
			// "type reason note"
			if parts := strings.SplitN(e, " ", 3); len(parts) != 3 || len(parts[2]) > maxEventNote {
				t.Errorf("%s: event %.60q... has a note of %d bytes", name, e, len(e))
			}
			if strings.Contains(e, "RequestID") {
				t.Errorf("%s: event %.60q... has the request ID", name, e)
			}
		default:
			if n == 0 {
				t.Errorf("%s: no events", name)
			}
			return
		}
	}
}

func TestStableText(t *testing.T) {
	a := fmt.Errorf("KMSIssuer x cannot sign now: reading the KMS key's public key: %w", awsError("GetPublicKey"))
	b := fmt.Errorf("KMSIssuer x cannot sign now: reading the KMS key's public key: %w", awsError("GetPublicKey"))
	if a.Error() == b.Error() {
		t.Fatal("the test errors don't differ")
	}
	want := "KMSIssuer x cannot sign now: reading the KMS key's public key: KMS GetPublicKey: " + accessDenied + ": " + accessDeniedMsg
	if got := stableText(a); got != want || stableText(b) != want {
		t.Errorf("stableText = %q, want %q", got, want)
	}
	// Joined (the alias clean-up), the operation error is still found.
	if got := stableText(errors.Join(fmt.Errorf("creating alias: %w", awsError("CreateAlias")), nil)); strings.Contains(got, "RequestID") {
		t.Errorf("joined: %q keeps the request ID", got)
	}
	// An operation error without an API error (a network failure) gets a fixed text.
	net := &smithy.OperationError{ServiceID: serviceKMS, OperationName: "Sign", Err: fmt.Errorf("dial tcp 10.0.0.1:%d: i/o timeout", requestIDs.Add(1))}
	if got := stableText(net); got != "KMS Sign failed (the controller log has the details)" {
		t.Errorf("network failure: %q", got)
	}
	if got := stableText(errKMSDown); got != errKMSDown.Error() {
		t.Errorf("an error from elsewhere changed: %q", got)
	}
}

// expectStable runs two passes that both meet a KMS error with a new request ID and
// checks that the second left the status as the first wrote it: a changed status
// makes a watch event, which starts the next pass at once, past the work queue's
// backoff. (The fake client bumps the resource version on every write, changed or
// not, so the status itself is compared.)
func expectStable(t *testing.T, name string, pass func() error, status func() any) {
	t.Helper()
	if err := pass(); err == nil {
		t.Fatalf("%s: a KMS error was swallowed", name)
	}
	first := status()
	if err := pass(); err == nil {
		t.Fatalf("%s: a KMS error was swallowed", name)
	}
	if second := status(); !apiequality.Semantic.DeepEqual(first, second) {
		t.Errorf("%s: the retry changed the status:\n%+v\n%+v", name, first, second)
	}
}

// A request KMS refuses to sign stays pending, and its retries don't rewrite it:
// whether Sign is refused (SigningFailed) or the issuer's public key can't be read
// (IssuerCannotSign).
func TestSigningFailureIsStable(t *testing.T) {
	for name, c := range map[string]struct {
		kms    func(*mocks.KMSMock) *deniedKMS
		reason string
	}{
		"Sign refused":         {func(m *mocks.KMSMock) *deniedKMS { return &deniedKMS{KMSMock: m, sign: true} }, eventSigningFailed},
		"GetPublicKey refused": {func(m *mocks.KMSMock) *deniedKMS { return &deniedKMS{KMSMock: m, publicKey: true} }, eventIssuerCannotSign},
	} {
		h := newRequestHarness(t, unitNow.Add(time.Hour))
		h.r.KMSCA = &kmsca.KMSCA{Client: c.kms(h.u.mock)}
		expectStable(t, name, h.reconcile, func() any { return h.request(t).Status })
		ready := readyCondition(h.request(t))
		if ready == nil || !strings.Contains(ready.Message, accessDenied+": "+accessDeniedMsg) || strings.Contains(ready.Message, "RequestID") {
			t.Errorf("%s: Ready condition %+v, want the KMS error's code and message without its request ID", name, ready)
		}
		found := false
		for _, e := range h.events() {
			found = found || strings.HasPrefix(e, "Warning "+c.reason+" ")
		}
		if !found {
			t.Errorf("%s: no Warning %s event", name, c.reason)
		}
	}
}

// An issuer whose public key KMS refuses isn't made ready, and its retries don't
// rewrite it. A long KMS message keeps its events, cut short.
func TestIssuerKMSErrorIsStable(t *testing.T) {
	for _, message := range []string{"", strings.Repeat("x", 2*maxEventNote)} {
		issuerKMSError(t, message)
	}
}

func issuerKMSError(t *testing.T, message string) {
	t.Helper()
	u := newUnitCA(t)
	issuer := &kmsiapi.KMSIssuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "i"},
		Spec: kmsiapi.KMSIssuerSpec{
			KeyID: u.issuingKey, IntermediateCertificate: string(encodeForTest(u.intermediate.Raw)),
			PermittedDNSDomains: []string{testDomain},
		},
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kmsiapi.AddToScheme(scheme)
	fc := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(issuer).WithStatusSubresource(issuer).Build()
	access, err := NewAccess([]string{testNamespace}, []string{u.issuingKey}, testCeilings, []*x509.Certificate{u.root}, unitNow)
	if err != nil {
		t.Fatal(err)
	}
	rec := events.NewFakeRecorder(10)
	r := &KMSIssuerReconciler{
		Client: fc, Log: logf.Log, Recorder: rec,
		KMSCA: &kmsca.KMSCA{Client: &deniedKMS{KMSMock: u.mock, publicKey: true, message: message}}, Access: access, Clock: fakeclock.NewFakeClock(unitNow.Add(time.Hour)),
	}
	key := client.ObjectKeyFromObject(issuer)
	get := func() *kmsiapi.KMSIssuer {
		got := &kmsiapi.KMSIssuer{}
		if err := fc.Get(context.TODO(), key, got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	expectStable(t, "GetPublicKey refused", func() error {
		_, err := r.Reconcile(context.TODO(), ctrl.Request{NamespacedName: key})
		return err
	}, func() any { return get().Status })
	if got := get(); got.Status.IsReady() || !strings.Contains(got.Status.Conditions[0].Message, accessDenied) {
		t.Errorf("status %+v, want not ready with the KMS error", got.Status)
	}
	expectNotesCut(t, "issuer", rec)
}

// A KMSKey whose alias KMS refuses isn't made ready, and its retries don't
// rewrite it. A long KMS message keeps its events, cut short.
func TestKMSKeyErrorIsStable(t *testing.T) {
	for _, message := range []string{"", strings.Repeat("x", 2*maxEventNote)} {
		kmsKeyError(t, message)
	}
}

func kmsKeyError(t *testing.T, message string) {
	t.Helper()
	kmsKey := &kmsiapi.KMSKey{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "k", UID: "uid-k"},
		Spec:       kmsiapi.KMSKeySpec{AliasName: "alias/refused", DeletionPolicy: retain},
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = kmsiapi.AddToScheme(scheme)
	fc := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(kmsKey).WithStatusSubresource(kmsKey).Build()
	rec := events.NewFakeRecorder(10)
	r := &KMSKeyReconciler{
		Client: fc, Log: logf.Log, Scheme: scheme, Recorder: rec,
		KMSCA: &kmsca.KMSCA{Client: &deniedKMS{KMSMock: mocks.New(), alias: true, message: message}},
	}
	key := client.ObjectKeyFromObject(kmsKey)
	get := func() *kmsiapi.KMSKey {
		got := &kmsiapi.KMSKey{}
		if err := fc.Get(context.TODO(), key, got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	expectStable(t, "CreateAlias refused", func() error {
		_, err := r.Reconcile(context.TODO(), ctrl.Request{NamespacedName: key})
		return err
	}, func() any { return get().Status })
	if got := get(); got.Status.IsReady() || !strings.Contains(got.Status.Conditions[0].Message, accessDenied) {
		t.Errorf("status %+v, want not ready with the KMS error", got.Status)
	}
	expectNotesCut(t, "KMSKey", rec)
}
