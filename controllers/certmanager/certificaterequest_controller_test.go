/*
Copyright 2020 Skyscanner Limited.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certmanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	fakeclock "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
)

var _ = Context("CertificateRequestReconciler", func() {
	var issuerKey client.ObjectKey

	BeforeEach(func() {
		issuerKey = client.ObjectKey{Name: "cr-issuer", Namespace: "default"}
		issuer := &kmsiapi.KMSIssuer{}
		if err := k8sClient.Get(context.Background(), issuerKey, issuer); err != nil {
			Expect(k8sClient.Create(context.Background(), newIssuer(issuerKey.Namespace, issuerKey.Name, allowedKeyID))).Should(Succeed())
		}
		WaitIssuerReady(issuerKey)
	})

	create := func(name string, mutate func(*cmapi.CertificateRequest), csr *x509.CertificateRequest, approve bool) client.ObjectKey {
		cr, err := newCertificateRequest(name, issuerKey.Name, csr)
		Expect(err).To(BeNil())
		cr.Namespace = issuerKey.Namespace
		if mutate != nil {
			mutate(cr)
		}
		Expect(k8sClient.Create(context.Background(), cr)).Should(Succeed())
		if approve {
			Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(cr), cr)).Should(Succeed())
			apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "Approved", "")
			Expect(k8sClient.Status().Update(context.Background(), cr)).Should(Succeed())
		}
		return client.ObjectKeyFromObject(cr)
	}
	get := func(key client.ObjectKey) *cmapi.CertificateRequest {
		cr := &cmapi.CertificateRequest{}
		Expect(k8sClient.Get(context.Background(), key, cr)).Should(Succeed())
		return cr
	}
	expectFailed := func(key client.ObjectKey) {
		Eventually(func() bool {
			return apiutil.CertificateRequestHasCondition(get(key), cmapi.CertificateRequestCondition{
				Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: cmapi.CertificateRequestReasonFailed,
			})
		}, time.Second*5, time.Millisecond*100).Should(BeTrue(), "request should be failed")
		Expect(get(key).Status.Certificate).To(BeEmpty())
	}
	expectUntouched := func(key client.ObjectKey) {
		Consistently(func() int {
			cr := get(key)
			n := len(cr.Status.Certificate)
			for _, c := range cr.Status.Conditions {
				if c.Type == cmapi.CertificateRequestConditionReady {
					n++
				}
			}
			return n
		}, time.Second*2, time.Millisecond*200).Should(Equal(0), "request should be left alone")
	}
	sans := func(names ...string) *x509.CertificateRequest {
		return &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}
	}

	It("signs an approved request within policy", func() {
		key := create("cr-good", nil, sans("svc.example.internal"), true)
		Eventually(func() int { return len(get(key).Status.Certificate) }, time.Second*5, time.Millisecond*100).ShouldNot(BeZero())

		cr := get(key)
		By("handing out the leaf followed by the intermediate, and the pinned root as ca.crt")
		block, rest := pem.Decode(cr.Status.Certificate)
		leaf, err := x509.ParseCertificate(block.Bytes)
		Expect(err).To(BeNil())
		block, rest = pem.Decode(rest)
		Expect(block).NotTo(BeNil())
		Expect(rest).To(BeEmpty())
		intermediate, err := x509.ParseCertificate(block.Bytes)
		Expect(err).To(BeNil())
		Expect(intermediate.MaxPathLenZero).To(BeTrue())
		Expect(leaf.IsCA).To(BeFalse())
		Expect(leaf.DNSNames).To(Equal([]string{"svc.example.internal"}))
		root, err := ParseCertificate(cr.Status.CA)
		Expect(err).To(BeNil())
		Expect(root.Equal(testRoot)).To(BeTrue())
		roots, inters := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(root)
		inters.AddCert(intermediate)
		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "svc.example.internal"})
		Expect(err).To(BeNil())
		Expect(leaf.NotAfter.After(intermediate.NotAfter)).To(BeFalse())
	})

	It("never signs an unapproved request", func() {
		expectUntouched(create("cr-unapproved", nil, sans("svc.example.internal"), false))
	})

	It("refuses a CA request", func() {
		expectFailed(create("cr-ca", func(cr *cmapi.CertificateRequest) { cr.Spec.IsCA = true }, sans("svc.example.internal"), true))
	})

	It("refuses a name outside the permitted domains", func() {
		expectFailed(create("cr-outside", nil, sans("accounts.google.com"), true))
	})

	It("refuses a duration over the issuer's maximum", func() {
		expectFailed(create("cr-long", func(cr *cmapi.CertificateRequest) {
			cr.Spec.Duration = &metav1.Duration{Duration: 20 * 365 * 24 * time.Hour}
		}, sans("svc.example.internal"), true))
	})

	It("refuses a usage a server certificate doesn't need", func() {
		expectFailed(create("cr-usage", func(cr *cmapi.CertificateRequest) {
			cr.Spec.Usages = []cmapi.KeyUsage{cmapi.UsageCertSign}
		}, sans("svc.example.internal"), true))
	})

	It("leaves requests with an empty issuerRef group alone", func() {
		expectUntouched(create("cr-nogroup", func(cr *cmapi.CertificateRequest) { cr.Spec.IssuerRef.Group = "" }, sans("svc.example.internal"), true))
	})

	It("leaves requests for another group alone", func() {
		expectUntouched(create("cr-othergroup", func(cr *cmapi.CertificateRequest) { cr.Spec.IssuerRef.Group = "cert-manager.io" }, sans("svc.example.internal"), true))
	})

	It("refuses another kind in its group", func() {
		expectFailed(create("cr-kind", func(cr *cmapi.CertificateRequest) { cr.Spec.IssuerRef.Kind = "KMSClusterIssuer" }, sans("svc.example.internal"), true))
	})

	It("refuses an issuer whose key is not allowed", func() {
		otherIssuer := client.ObjectKey{Name: "cr-issuer-other-key", Namespace: "default"}
		Expect(k8sClient.Create(context.Background(), newIssuer(otherIssuer.Namespace, otherIssuer.Name, otherKeyID))).Should(Succeed())
		expectFailed(create("cr-other-key", func(cr *cmapi.CertificateRequest) { cr.Spec.IssuerRef.Name = otherIssuer.Name }, sans("svc.example.internal"), true))
	})
})

func TestRequestShouldBeProcessed(t *testing.T) {
	fixedTime := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	fclock := fakeclock.NewFakeClock(fixedTime)

	tests := map[string]struct {
		conds []cmapi.CertificateRequestCondition

		expConds         []cmapi.CertificateRequestCondition
		expShouldProcess bool
		expEvent         *string
		expFailureTime   *metav1.Time
	}{
		"if request has true ready condition, exit false": {
			conds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionTrue, Reason: cmapi.CertificateRequestReasonIssued},
			},
			expConds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionTrue, Reason: cmapi.CertificateRequestReasonIssued},
			},
		},
		"if request has ready condition reason failed, exit false": {
			conds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: cmapi.CertificateRequestReasonFailed},
			},
			expConds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: cmapi.CertificateRequestReasonFailed},
			},
		},
		"if request has ready condition reason denied, exit false": {
			conds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: cmapi.CertificateRequestReasonDenied},
			},
			expConds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: cmapi.CertificateRequestReasonDenied},
			},
		},
		"if request has been denied, exit false and update ready reason with ready denied": {
			conds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue, Reason: "Denied"},
			},
			expConds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue, Reason: "Denied"},
				{
					Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: cmapi.CertificateRequestReasonDenied,
					Message: "The CertificateRequest was denied by an approval controller", LastTransitionTime: &metav1.Time{Time: fixedTime},
				},
			},
			expEvent:       strP("Warning Denied The CertificateRequest was denied by an approval controller"),
			expFailureTime: &metav1.Time{Time: fixedTime},
		},
		"if request has not been approved, return false": {
			conds:    []cmapi.CertificateRequestCondition{},
			expConds: []cmapi.CertificateRequestCondition{},
		},
		"if request has been approved, return true": {
			conds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionApproved, Status: cmmeta.ConditionTrue, Reason: "Approved"},
			},
			expConds: []cmapi.CertificateRequestCondition{
				{Type: cmapi.CertificateRequestConditionApproved, Status: cmmeta.ConditionTrue, Reason: "Approved"},
			},
			expShouldProcess: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			apiutil.Clock = fclock
			scheme := runtime.NewScheme()
			_ = clientgoscheme.AddToScheme(scheme)
			_ = cmapi.AddToScheme(scheme)

			request := &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cr", Namespace: "test-ns"},
				Status:     cmapi.CertificateRequestStatus{Conditions: test.conds},
			}

			fclient := fakeclient.NewClientBuilder().
				WithObjects(request).
				WithStatusSubresource(request).
				WithScheme(scheme).
				Build()

			fakeRecorder := record.NewFakeRecorder(1)

			c := CertificateRequestReconciler{
				Client:   fclient,
				Log:      logf.Log,
				Recorder: fakeRecorder,
				Clock:    fclock,
			}

			shouldProcess, err := c.requestShouldBeProcessed(context.TODO(), logf.Log, request)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			if shouldProcess != test.expShouldProcess {
				t.Errorf("unexpected shouldProcess, exp=%t got=%t", test.expShouldProcess, shouldProcess)
			}
			if !apiequality.Semantic.DeepEqual(request.Status.Conditions, test.expConds) {
				t.Errorf("unexpected conditions, exp=%#+v got=%#+v", test.expConds, request.Status.Conditions)
			}
			if !apiequality.Semantic.DeepEqual(request.Status.FailureTime, test.expFailureTime) {
				t.Errorf("unexpected failureTime, exp=%#+v got=%#+v", test.expFailureTime, request.Status.FailureTime)
			}

			select {
			case event := <-fakeRecorder.Events:
				if test.expEvent == nil {
					t.Errorf("expected no event, got='%s'", event)
				} else if *test.expEvent != event {
					t.Errorf("unexpected event, exp='%s' got='%s'", *test.expEvent, event)
				}
			default:
				if test.expEvent != nil {
					t.Errorf("unexpected event, exp='%s' got=''", *test.expEvent)
				}
			}
		})
	}
}

func strP(s string) *string {
	return &s
}

// newCertificateRequest creates a CertificateRequest for our issuer with a CSR made
// from template.
func newCertificateRequest(name, issuerName string, template *x509.CertificateRequest) (*cmapi.CertificateRequest, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: cmapi.CertificateRequestSpec{
			Request:  csrPEM,
			Duration: &metav1.Duration{Duration: 24 * time.Hour},
			IssuerRef: cmmeta.IssuerReference{
				Name:  issuerName,
				Kind:  issuerKind,
				Group: kmsiapi.GroupVersion.Group,
			},
		},
	}, nil
}
