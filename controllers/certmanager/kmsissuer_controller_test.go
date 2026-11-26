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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
)

func WaitIssuerReady(key client.ObjectKey) *kmsiapi.KMSIssuer {
	issuer := &kmsiapi.KMSIssuer{}
	Eventually(
		func() bool {
			Expect(k8sClient.Get(context.Background(), key, issuer)).Should(Succeed(), "failed to get KMSIssuer resource")
			return issuer.Status.IsReady()
		},
		time.Second*5, time.Millisecond*100,
	).Should(BeTrue(), "issuer should be ready")
	return issuer
}

func newIssuer(namespace, name, keyID string) *kmsiapi.KMSIssuer {
	return &kmsiapi.KMSIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: kmsiapi.KMSIssuerSpec{
			KeyID:                   keyID,
			IntermediateCertificate: intermediateFor(keyID),
			PermittedDNSDomains:     []string{testDomain},
		},
	}
}

func expectIssuerNeverReady(key client.ObjectKey) {
	Consistently(func() bool {
		issuer := &kmsiapi.KMSIssuer{}
		if err := k8sClient.Get(context.Background(), key, issuer); err != nil {
			return false
		}
		return issuer.Status.IsReady() || len(issuer.Status.Certificate) > 0
	}, time.Second*2, time.Millisecond*200).Should(BeFalse(), "issuer must not become ready or get a certificate")
}

var _ = Context("KMSIssuer", func() {

	Describe("when a new resource is created", func() {
		It("should accept the intermediate the pinned root signed for its key", func() {
			key := client.ObjectKey{Name: testIssuer, Namespace: testNamespace}
			Expect(k8sClient.Create(context.Background(), newIssuer(key.Namespace, key.Name, allowedKeyID))).Should(Succeed())

			issuer := WaitIssuerReady(key)
			cert, err := ParseCertificate(issuer.Status.Certificate)
			Expect(err).To(BeNil())
			Expect(cert.MaxPathLenZero).To(BeTrue())
			Expect(cert.CheckSignatureFrom(testRoot)).To(Succeed())
		})

		It("should refuse an intermediate for another key", func() {
			key := client.ObjectKey{Name: "issuer-swapped", Namespace: testNamespace}
			issuer := newIssuer(key.Namespace, key.Name, allowedKeyID)
			issuer.Spec.IntermediateCertificate = otherIntermediate
			Expect(k8sClient.Create(context.Background(), issuer)).Should(Succeed())
			expectIssuerNeverReady(key)
		})

		It("should refuse the root itself as the intermediate", func() {
			key := client.ObjectKey{Name: "issuer-root", Namespace: testNamespace}
			issuer := newIssuer(key.Namespace, key.Name, allowedKeyID)
			issuer.Spec.IntermediateCertificate = string(ParseableRoot())
			Expect(k8sClient.Create(context.Background(), issuer)).Should(Succeed())
			expectIssuerNeverReady(key)
		})

		It("should refuse a key that is not allowed", func() {
			key := client.ObjectKey{Name: "issuer-other-key", Namespace: testNamespace}
			Expect(k8sClient.Create(context.Background(), newIssuer(key.Namespace, key.Name, otherKeyID))).Should(Succeed())
			expectIssuerNeverReady(key)
		})

		It("should refuse a namespace that is not allowed", func() {
			Expect(k8sClient.Create(context.Background(), &core.Namespace{ObjectMeta: metav1.ObjectMeta{Name: otherNamespace}})).Should(Succeed())
			key := client.ObjectKey{Name: testIssuer, Namespace: otherNamespace}
			Expect(k8sClient.Create(context.Background(), newIssuer(key.Namespace, key.Name, allowedKeyID))).Should(Succeed())
			expectIssuerNeverReady(key)
		})

		It("should refuse domains outside the operator's ceiling", func() {
			key := client.ObjectKey{Name: "issuer-wide", Namespace: testNamespace}
			issuer := newIssuer(key.Namespace, key.Name, allowedKeyID)
			issuer.Spec.PermittedDNSDomains = []string{tldCom}
			Expect(k8sClient.Create(context.Background(), issuer)).Should(Succeed())
			expectIssuerNeverReady(key)
		})

		It("should refuse an alias as keyId at the API", func() {
			issuer := newIssuer(testNamespace, "issuer-alias", "alias/allowed")
			Expect(k8sClient.Create(context.Background(), issuer)).ShouldNot(Succeed())
		})

		It("should refuse an issuer without permitted domains or an intermediate at the API", func() {
			issuer := newIssuer(testNamespace, "issuer-no-domains", allowedKeyID)
			issuer.Spec.PermittedDNSDomains = nil
			Expect(k8sClient.Create(context.Background(), issuer)).ShouldNot(Succeed())
			issuer = newIssuer(testNamespace, "issuer-no-intermediate", allowedKeyID)
			issuer.Spec.IntermediateCertificate = ""
			Expect(k8sClient.Create(context.Background(), issuer)).ShouldNot(Succeed())
		})

		It("should refuse changing keyId", func() {
			key := client.ObjectKey{Name: "issuer-immutable", Namespace: testNamespace}
			Expect(k8sClient.Create(context.Background(), newIssuer(key.Namespace, key.Name, allowedKeyID))).Should(Succeed())
			issuer := WaitIssuerReady(key)
			issuer.Spec.KeyID = otherKeyID
			Expect(k8sClient.Update(context.Background(), issuer)).ShouldNot(Succeed())
		})
	})
})

// ParseableRoot is the suite's root certificate, PEM.
func ParseableRoot() []byte {
	return encodeForTest(testRoot.Raw)
}
