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
			KeyID:               keyID,
			CommonName:          "Test Root CA",
			PermittedDNSDomains: []string{"example.internal"},
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
		It("should make a constrained CA certificate", func() {
			key := client.ObjectKey{Name: "issuer", Namespace: "default"}
			Expect(k8sClient.Create(context.Background(), newIssuer(key.Namespace, key.Name, allowedKeyID))).Should(Succeed())

			issuer := WaitIssuerReady(key)
			cert, err := ParseCertificate(issuer.Status.Certificate)
			Expect(err).To(BeNil())
			Expect(cert.NotAfter.Sub(cert.NotBefore)).To(Equal(defaultCertDuration))
			Expect(cert.PermittedDNSDomains).To(Equal([]string{"example.internal"}))
			Expect(cert.MaxPathLenZero).To(BeTrue())

			By("not re-making it on later reconciles")
			serial := cert.SerialNumber
			Consistently(func() string {
				Expect(k8sClient.Get(context.Background(), key, issuer)).Should(Succeed())
				c, _ := ParseCertificate(issuer.Status.Certificate)
				return c.SerialNumber.String()
			}, time.Second*2, time.Millisecond*200).Should(Equal(serial.String()))
		})

		It("should refuse a key that is not allowed", func() {
			key := client.ObjectKey{Name: "issuer-other-key", Namespace: "default"}
			Expect(k8sClient.Create(context.Background(), newIssuer(key.Namespace, key.Name, otherKeyID))).Should(Succeed())
			expectIssuerNeverReady(key)
		})

		It("should refuse a namespace that is not allowed", func() {
			Expect(k8sClient.Create(context.Background(), &core.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "elsewhere"}})).Should(Succeed())
			key := client.ObjectKey{Name: "issuer", Namespace: "elsewhere"}
			Expect(k8sClient.Create(context.Background(), newIssuer(key.Namespace, key.Name, allowedKeyID))).Should(Succeed())
			expectIssuerNeverReady(key)
		})

		It("should refuse domains outside the operator's ceiling", func() {
			key := client.ObjectKey{Name: "issuer-wide", Namespace: "default"}
			issuer := newIssuer(key.Namespace, key.Name, allowedKeyID)
			issuer.Spec.PermittedDNSDomains = []string{"com"}
			Expect(k8sClient.Create(context.Background(), issuer)).Should(Succeed())
			expectIssuerNeverReady(key)
		})

		It("should refuse an alias as keyId at the API", func() {
			issuer := newIssuer("default", "issuer-alias", "alias/allowed")
			Expect(k8sClient.Create(context.Background(), issuer)).ShouldNot(Succeed())
		})

		It("should refuse an issuer without permitted domains at the API", func() {
			issuer := newIssuer("default", "issuer-no-domains", allowedKeyID)
			issuer.Spec.PermittedDNSDomains = nil
			Expect(k8sClient.Create(context.Background(), issuer)).ShouldNot(Succeed())
		})

		It("should refuse renewBefore not shorter than duration at the API", func() {
			issuer := newIssuer("default", "issuer-loop", allowedKeyID)
			issuer.Spec.Duration = &metav1.Duration{Duration: 48 * time.Hour}
			issuer.Spec.RenewBefore = &metav1.Duration{Duration: 48 * time.Hour}
			Expect(k8sClient.Create(context.Background(), issuer)).ShouldNot(Succeed())
		})

		It("should refuse changing keyId or commonName", func() {
			key := client.ObjectKey{Name: "issuer-immutable", Namespace: "default"}
			Expect(k8sClient.Create(context.Background(), newIssuer(key.Namespace, key.Name, allowedKeyID))).Should(Succeed())
			issuer := WaitIssuerReady(key)
			issuer.Spec.CommonName = "Another CA"
			Expect(k8sClient.Update(context.Background(), issuer)).ShouldNot(Succeed())
			Expect(k8sClient.Get(context.Background(), key, issuer)).Should(Succeed())
			issuer.Spec.KeyID = otherKeyID
			Expect(k8sClient.Update(context.Background(), issuer)).ShouldNot(Succeed())
		})
	})
})
