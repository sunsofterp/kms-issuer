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

package kmsca_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	mocks "github.com/sunsofterp/kms-issuer/v5/pkg/kmsmock"
)

const owner = "0d3c5e1e-0000-4000-8000-000000000001"

// newKey creates a key owned by owner.
func newKey(client *kmsca.KMSCA, alias string) string {
	keyID, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: alias, OwnerUID: owner})
	Expect(err).To(BeNil())
	return keyID
}

func caInput(name string, duration time.Duration, now time.Time, domains ...string) *kmsca.CAInput {
	if len(domains) == 0 {
		domains = []string{"example.internal"}
	}
	return &kmsca.CAInput{Subject: pkix.Name{CommonName: name}, PermittedDNSDomains: domains, Duration: duration, Now: now}
}

// twoTier makes a root and an intermediate on separate keys.
type twoTier struct {
	client                  *kmsca.KMSCA
	rootKeyID, issuingKeyID string
	root, intermediate      *x509.Certificate
	now                     time.Time
	expectedForIntermediate kmsca.ExpectedIntermediate
}

func newTwoTier() *twoTier {
	t := &twoTier{client: mockKMSCA(), now: time.Now()}
	t.rootKeyID = newKey(t.client, "alias/root")
	t.issuingKeyID = newKey(t.client, "alias/issuing")
	var err error
	t.root, err = t.client.MakeRoot(context.TODO(), t.rootKeyID, caInput("Test Root", 20*365*24*time.Hour, t.now))
	Expect(err).To(BeNil())
	t.intermediate, err = t.client.MakeIntermediate(context.TODO(), t.rootKeyID, t.root, t.issuingKeyID, caInput("Test Issuing", 90*24*time.Hour, t.now))
	Expect(err).To(BeNil())
	pub, err := t.client.PublicKey(context.TODO(), t.issuingKeyID)
	Expect(err).To(BeNil())
	t.expectedForIntermediate = kmsca.ExpectedIntermediate{Roots: []*x509.Certificate{t.root}, PublicKey: pub, AllowedDomains: []string{"example.internal"}, Now: t.now}
	return t
}

// validateErr is ValidateIntermediate's error alone.
func validateErr(cert *x509.Certificate, expected kmsca.ExpectedIntermediate) error {
	_, err := kmsca.ValidateIntermediate(cert, expected)
	return err
}

var _ = Context("KMSCA", func() {

	Describe("when calling CreateKey", func() {
		It("should create a key tagged with its owner, and an alias", func() {
			client := mockKMSCA()
			keyID, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName:             "alias/test-key",
				OwnerUID:              owner,
				Tags:                  map[string]string{"Project": "k8s", kmsca.OwnerTag: "forged"},
				Description:           "My test key",
				CustomerMasterKeySpec: "RSA_2048",
				Policy:                "{}",
			})
			Expect(err).To(BeNil())
			tags, err := client.Client.ListResourceTags(context.TODO(), &kms.ListResourceTagsInput{KeyId: aws.String(keyID)})
			Expect(err).To(BeNil())
			found := map[string]string{}
			for _, t := range tags.Tags {
				found[aws.ToString(t.TagKey)] = aws.ToString(t.TagValue)
			}
			Expect(found).To(HaveKeyWithValue(kmsca.OwnerTag, owner))
			Expect(found).To(HaveKeyWithValue("Project", "k8s"))
		})

		It("should return the key it created before", func() {
			client := mockKMSCA()
			keyID := newKey(client, "alias/test-key")
			Expect(newKey(client, "alias/test-key")).To(Equal(keyID))
		})

		It("should refuse to adopt a key it did not create", func() {
			client := mockKMSCA()
			newKey(client, "alias/someone-elses")
			_, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/someone-elses", OwnerUID: "another-owner"})
			Expect(err).To(MatchError(kmsca.ErrAliasTaken))
		})

		It("should refuse without an owner, or with a key ID in place of an alias", func() {
			client := mockKMSCA()
			_, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/x"})
			Expect(err).NotTo(BeNil())
			_, err = client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "arn:aws:kms:us-east-1:111122223333:key/abc", OwnerUID: owner})
			Expect(err).NotTo(BeNil())
		})

		It("should schedule the new key's deletion when the alias can't be created", func() {
			mock := mocks.New()
			mock.FailCreateAlias = true
			client := &kmsca.KMSCA{Client: mock}
			_, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/x", OwnerUID: owner})
			Expect(err).NotTo(BeNil())
			keyIDs := mock.KeyIDs()
			Expect(keyIDs).To(HaveLen(1))
			Expect(mock.PendingDeletion(keyIDs[0])).To(BeTrue(), "the key made is pending deletion")
		})
	})

	Describe("when calling DeleteKey", func() {
		It("should delete the key it created and its alias", func() {
			mock := mocks.New()
			client := &kmsca.KMSCA{Client: mock}
			keyID := newKey(client, "alias/test-key")
			Expect(client.DeleteKey(context.TODO(), &kmsca.DeleteKeyInput{AliasName: "alias/test-key", OwnerUID: owner})).To(Succeed())
			Expect(mock.PendingDeletion(keyID)).To(BeTrue())
			_, err := client.Client.DescribeKey(context.TODO(), &kms.DescribeKeyInput{KeyId: aws.String("alias/test-key")})
			Expect(err).To(BeAssignableToTypeOf(&kmstypes.NotFoundException{}))

			By("treating a missing alias as nothing left to delete")
			Expect(client.DeleteKey(context.TODO(), &kmsca.DeleteKeyInput{AliasName: "alias/test-key", OwnerUID: owner})).To(Succeed())
		})

		It("should finish a deletion whose alias removal failed before", func() {
			mock := mocks.New()
			client := &kmsca.KMSCA{Client: mock}
			keyID := newKey(client, "alias/test-key")
			_, err := mock.ScheduleKeyDeletion(context.TODO(), &kms.ScheduleKeyDeletionInput{KeyId: aws.String(keyID)})
			Expect(err).To(BeNil())
			Expect(client.DeleteKey(context.TODO(), &kmsca.DeleteKeyInput{AliasName: "alias/test-key", OwnerUID: owner})).To(Succeed())
		})

		It("should refuse to delete a key it did not create", func() {
			mock := mocks.New()
			client := &kmsca.KMSCA{Client: mock}
			keyID := newKey(client, "alias/test-key")
			err := client.DeleteKey(context.TODO(), &kmsca.DeleteKeyInput{AliasName: "alias/test-key", OwnerUID: "another-owner"})
			Expect(err).To(MatchError(kmsca.ErrNotOwned))
			Expect(mock.PendingDeletion(keyID)).To(BeFalse())
		})
	})

	Describe("the two tiers", func() {
		It("makes a constrained path-length-1 root and a constrained path-length-0 intermediate on another key", func() {
			t := newTwoTier()
			Expect(kmsca.ValidateRoot(t.root, t.now)).To(Succeed())
			Expect(t.root.MaxPathLen).To(Equal(1))
			Expect(t.root.PermittedDNSDomainsCritical).To(BeTrue())
			Expect(t.root.ExcludedIPRanges).To(HaveLen(2))

			Expect(t.intermediate.IsCA).To(BeTrue())
			Expect(t.intermediate.MaxPathLenZero).To(BeTrue())
			Expect(t.intermediate.PermittedDNSDomains).To(Equal([]string{"example.internal"}))
			Expect(t.intermediate.ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
			Expect(t.root.ExtKeyUsage).To(BeEmpty())
			Expect(t.intermediate.KeyUsage).To(Equal(x509.KeyUsageCertSign | x509.KeyUsageCRLSign))
			Expect(t.intermediate.Issuer.CommonName).To(Equal("Test Root"))
			Expect(t.intermediate.PublicKey).NotTo(Equal(t.root.PublicKey))
			Expect(validateErr(t.intermediate, t.expectedForIntermediate)).To(Succeed())
			Expect(len(t.intermediate.SerialNumber.Bytes())).To(BeNumerically("<=", 16))
		})

		It("refuses an intermediate that would outlive the root, or last over 183 days", func() {
			client := mockKMSCA()
			rootKey, issuingKey := newKey(client, "alias/r"), newKey(client, "alias/i")
			now := time.Now()
			root, err := client.MakeRoot(context.TODO(), rootKey, caInput("Root", 48*time.Hour, now))
			Expect(err).To(BeNil())
			_, err = client.MakeIntermediate(context.TODO(), rootKey, root, issuingKey, caInput("Issuing", 72*time.Hour, now))
			Expect(err).NotTo(BeNil())

			t := newTwoTier()
			_, err = t.client.MakeIntermediate(context.TODO(), t.rootKeyID, t.root, t.issuingKeyID, caInput("Long", kmsca.MaxIntermediateDuration+24*time.Hour, t.now))
			Expect(err).NotTo(BeNil())
		})

		It("refuses an intermediate named like the root, and invalid constraint domains", func() {
			t := newTwoTier()
			_, err := t.client.MakeIntermediate(context.TODO(), t.rootKeyID, t.root, t.issuingKeyID, caInput("Test Root", 48*time.Hour, t.now))
			Expect(err).NotTo(BeNil())
			for _, d := range []string{"com", "internal", "*.example.internal", "Example.internal", ".example.internal", "example.internal."} {
				_, err := kmsca.CATemplate(caInput("X", 48*time.Hour, t.now, d), kmsca.Root)
				Expect(err).NotTo(BeNil(), d)
			}
		})

		It("refuses an intermediate wider than the root, on the root key, or with the wrong root key", func() {
			t := newTwoTier()
			_, err := t.client.MakeIntermediate(context.TODO(), t.rootKeyID, t.root, t.issuingKeyID, caInput("Wide", 48*time.Hour, t.now, "com"))
			Expect(err).NotTo(BeNil())
			_, err = t.client.MakeIntermediate(context.TODO(), t.rootKeyID, t.root, t.rootKeyID, caInput("Same", 48*time.Hour, t.now))
			Expect(err).NotTo(BeNil())
			_, err = t.client.MakeIntermediate(context.TODO(), t.issuingKeyID, t.root, newKey(t.client, "alias/x"), caInput("Wrong root key", 48*time.Hour, t.now))
			Expect(err).NotTo(BeNil())
		})

		It("leaves under the intermediate chain to the root and honor its constraints", func() {
			t := newTwoTier()
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			leaf := func(name string) *x509.Certificate {
				return &x509.Certificate{
					SerialNumber: big.NewInt(1658), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
					NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
				}
			}
			roots, inters := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(t.root)
			inters.AddCert(t.intermediate)

			signed, err := t.client.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{
				KeyID: t.issuingKeyID, Cert: leaf("svc.example.internal"), Parent: t.intermediate, PublicKey: key.Public(),
			})
			Expect(err).To(BeNil())
			_, err = signed.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "svc.example.internal"})
			Expect(err).To(BeNil())

			By("checking a name outside the constraints fails verification even if signed")
			outside, err := t.client.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{
				KeyID: t.issuingKeyID, Cert: leaf("accounts.google.com"), Parent: t.intermediate, PublicKey: key.Public(),
			})
			Expect(err).To(BeNil())
			_, err = outside.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "accounts.google.com"})
			Expect(err).NotTo(BeNil())

			By("refusing to sign under the intermediate with the root key")
			_, err = t.client.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{
				KeyID: t.rootKeyID, Cert: leaf("svc.example.internal"), Parent: t.intermediate, PublicKey: key.Public(),
			})
			Expect(err).NotTo(BeNil())
		})
	})

	Describe("ValidateIntermediate", func() {
		It("refuses an intermediate from another root with the same name", func() {
			t := newTwoTier()
			otherRootKey := newKey(t.client, "alias/other-root")
			otherRoot, err := t.client.MakeRoot(context.TODO(), otherRootKey, caInput("Test Root", 20*365*24*time.Hour, t.now))
			Expect(err).To(BeNil())
			forged, err := t.client.MakeIntermediate(context.TODO(), otherRootKey, otherRoot, t.issuingKeyID, caInput("Test Issuing", 48*time.Hour, t.now))
			Expect(err).To(BeNil())
			Expect(validateErr(forged, t.expectedForIntermediate)).NotTo(Succeed())
		})

		It("refuses constraints outside the allowed domains, another key, or an expired intermediate", func() {
			t := newTwoTier()
			other := t.expectedForIntermediate
			other.AllowedDomains = []string{"other.internal"}
			Expect(validateErr(t.intermediate, other)).NotTo(Succeed())

			other = t.expectedForIntermediate
			other.Now = t.intermediate.NotAfter.Add(time.Second)
			Expect(validateErr(t.intermediate, other)).NotTo(Succeed())

			otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			other = t.expectedForIntermediate
			other.PublicKey = otherKey.Public()
			Expect(validateErr(t.intermediate, other)).NotTo(Succeed())

			By("refusing the root itself as an intermediate")
			rootPub, _ := t.client.PublicKey(context.TODO(), t.rootKeyID)
			other = t.expectedForIntermediate
			other.PublicKey = rootPub
			Expect(validateErr(t.root, other)).NotTo(Succeed())
		})

		It("accepts only server auth as the extended key usage, and at most 183 days", func() {
			t := newTwoTier()
			pub, err := t.client.PublicKey(context.TODO(), t.issuingKeyID)
			Expect(err).To(BeNil())
			// sign makes an intermediate from the root key's template after mutate.
			sign := func(mutate func(*x509.Certificate)) *x509.Certificate {
				tmpl, err := kmsca.CATemplate(caInput("Hand Signed", 48*time.Hour, t.now), kmsca.Intermediate)
				Expect(err).To(BeNil())
				mutate(tmpl)
				cert, err := t.client.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{
					KeyID: t.rootKeyID, Cert: tmpl, Parent: t.root, PublicKey: pub,
				})
				Expect(err).To(BeNil())
				return cert
			}
			Expect(validateErr(sign(func(*x509.Certificate) {}), t.expectedForIntermediate)).To(Succeed())
			for name, eku := range map[string][]x509.ExtKeyUsage{
				"none":                 nil,
				"server and client":    {x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				"any":                  {x509.ExtKeyUsageAny},
				"client only":          {x509.ExtKeyUsageClientAuth},
				"server and code sign": {x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
			} {
				By("refusing extended key usage: " + name)
				Expect(validateErr(sign(func(c *x509.Certificate) { c.ExtKeyUsage = eku }), t.expectedForIntermediate)).NotTo(Succeed())
			}
			at := sign(func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(kmsca.MaxIntermediateDuration) })
			Expect(validateErr(at, t.expectedForIntermediate)).To(Succeed())
			over := sign(func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(kmsca.MaxIntermediateDuration + time.Second) })
			Expect(validateErr(over, t.expectedForIntermediate)).NotTo(Succeed())
		})

		It("refuses an unconstrained intermediate signed by the root key", func() {
			t := newTwoTier()
			rootSignerCA := t.client
			tmpl, err := kmsca.CATemplate(caInput("Unconstrained", 48*time.Hour, t.now), kmsca.Intermediate)
			Expect(err).To(BeNil())
			tmpl.PermittedDNSDomains = nil
			tmpl.PermittedURIDomains = nil
			tmpl.PermittedEmailAddresses = nil
			tmpl.ExcludedIPRanges = nil
			tmpl.PermittedDNSDomainsCritical = false
			pub, _ := rootSignerCA.PublicKey(context.TODO(), t.issuingKeyID)
			unconstrained, err := rootSignerCA.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{
				KeyID: t.rootKeyID, Cert: tmpl, Parent: t.root, PublicKey: pub,
			})
			Expect(err).To(BeNil())
			Expect(validateErr(unconstrained, t.expectedForIntermediate)).NotTo(Succeed())
		})
	})

	Describe("ParseCertificatePEM", func() {
		It("accepts exactly one certificate and nothing else", func() {
			t := newTwoTier()
			one := kmsca.EncodeCertificatePEM(t.root)
			_, err := kmsca.ParseCertificatePEM(one)
			Expect(err).To(BeNil())
			_, err = kmsca.ParseCertificatePEM(append(append([]byte{}, one...), one...))
			Expect(err).NotTo(BeNil())
			_, err = kmsca.ParseCertificatePEM(append([]byte("junk\n"), one...))
			Expect(err).NotTo(BeNil())
			_, err = kmsca.ParseCertificatePEM([]byte("not a certificate"))
			Expect(err).NotTo(BeNil())
		})
	})

	Describe("RandomSerial", func() {
		It("is positive and fits RFC 5280", func() {
			for range 1000 {
				s, err := kmsca.RandomSerial()
				Expect(err).To(BeNil())
				Expect(s.Sign()).To(Equal(1))
				Expect(s.BitLen()).To(BeNumerically("<=", 128))
			}
		})
	})
})

// mockKMSCA returns a KMSCA client with a mock of KMS backend.
func mockKMSCA() *kmsca.KMSCA {
	return &kmsca.KMSCA{
		Client: mocks.New(),
	}
}
