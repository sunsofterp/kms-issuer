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

func newCA(client *kmsca.KMSCA, keyID string, now time.Time) *x509.Certificate {
	ca, err := client.GenerateAndSignCertificateAuthorityCertificate(context.TODO(), &kmsca.GenerateCertificateAuthorityCertificateInput{
		KeyID: keyID, Subject: pkix.Name{CommonName: "Test CA"}, Duration: 24 * time.Hour,
		PermittedDNSDomains: []string{"example.internal"}, Now: now,
	})
	Expect(err).To(BeNil())
	return ca
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

	Describe("the CA certificate", func() {
		It("is a path-length-0 root, name-constrained to its domains, with a random short serial", func() {
			client := mockKMSCA()
			keyID := newKey(client, "alias/test-key")
			now := time.Now()
			ca := newCA(client, keyID, now)
			Expect(ca.IsCA).To(BeTrue())
			Expect(ca.MaxPathLenZero).To(BeTrue())
			Expect(ca.MaxPathLen).To(Equal(0))
			Expect(ca.PermittedDNSDomainsCritical).To(BeTrue())
			Expect(ca.PermittedDNSDomains).To(Equal([]string{"example.internal"}))
			Expect(ca.ExcludedIPRanges).To(HaveLen(2))
			Expect(ca.ExtKeyUsage).To(BeEmpty())
			Expect(ca.KeyUsage).To(Equal(x509.KeyUsageCertSign | x509.KeyUsageCRLSign))
			Expect(ca.NotAfter.Sub(ca.NotBefore)).To(Equal(24 * time.Hour))
			Expect(ca.NotBefore.Before(now)).To(BeTrue())
			Expect(ca.SerialNumber.Sign()).To(Equal(1))
			Expect(len(ca.SerialNumber.Bytes())).To(BeNumerically("<=", 16))
			Expect(newCA(client, keyID, now).SerialNumber).NotTo(Equal(ca.SerialNumber))

			roots := x509.NewCertPool()
			roots.AddCert(ca)
			_, err := ca.Verify(x509.VerifyOptions{Roots: roots})
			Expect(err).To(BeNil())
		})

		It("needs a permitted domain", func() {
			_, err := kmsca.CertificateAuthorityTemplate(&kmsca.GenerateCertificateAuthorityCertificateInput{Duration: time.Hour, Now: time.Now()})
			Expect(err).NotTo(BeNil())
		})
	})

	Describe("ValidateCA", func() {
		var (
			client   *kmsca.KMSCA
			keyID    string
			ca       *x509.Certificate
			expected kmsca.ExpectedCA
		)
		BeforeEach(func() {
			client = mockKMSCA()
			keyID = newKey(client, "alias/test-key")
			now := time.Now()
			ca = newCA(client, keyID, now)
			pub, err := client.PublicKey(context.TODO(), keyID)
			Expect(err).To(BeNil())
			expected = kmsca.ExpectedCA{PublicKey: pub, CommonName: "Test CA", PermittedDNSDomains: []string{"example.internal"}, Now: now}
		})

		It("accepts the certificate it made", func() {
			Expect(kmsca.ValidateCA(ca, expected)).To(Succeed())
		})

		It("refuses a certificate with the KMS public key but signed by another key", func() {
			// An attacker's own "root" with the same name signs a certificate carrying
			// the KMS public key and every expected field.
			otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			attackerRoot := *ca
			attackerRoot.PublicKey = otherKey.Public()
			tmpl := *ca
			der, err := x509.CreateCertificate(rand.Reader, &tmpl, &attackerRoot, ca.PublicKey, otherKey)
			Expect(err).To(BeNil())
			planted, err := x509.ParseCertificate(der)
			Expect(err).To(BeNil())
			Expect(kmsca.ValidateCA(planted, expected)).NotTo(Succeed())
		})

		It("refuses other domains, names, or an expired certificate", func() {
			other := expected
			other.PermittedDNSDomains = []string{"other.internal"}
			Expect(kmsca.ValidateCA(ca, other)).NotTo(Succeed())
			other = expected
			other.CommonName = "Another CA"
			Expect(kmsca.ValidateCA(ca, other)).NotTo(Succeed())
			other = expected
			other.Now = ca.NotAfter.Add(time.Second)
			Expect(kmsca.ValidateCA(ca, other)).NotTo(Succeed())
			otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			other = expected
			other.PublicKey = otherKey.Public()
			Expect(kmsca.ValidateCA(ca, other)).NotTo(Succeed())
		})
	})

	Describe("ParseCertificatePEM", func() {
		It("accepts exactly one certificate and nothing else", func() {
			client := mockKMSCA()
			ca := newCA(client, newKey(client, "alias/test-key"), time.Now())
			one := kmsca.EncodeCertificatePEM(ca)
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

	Describe("when calling SignCertificate", func() {
		var (
			client *kmsca.KMSCA
			keyID  string
			parent *x509.Certificate
		)
		BeforeEach(func() {
			client = mockKMSCA()
			keyID = newKey(client, "alias/test-key")
			parent = newCA(client, keyID, time.Now())
		})

		leaf := func(name string) *x509.Certificate {
			return &x509.Certificate{
				SerialNumber: big.NewInt(1658),
				Subject:      pkix.Name{CommonName: name},
				DNSNames:     []string{name},
				NotBefore:    time.Now().Add(-time.Minute),
				NotAfter:     time.Now().Add(time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				KeyUsage:     x509.KeyUsageDigitalSignature,
			}
		}

		It("should sign a leaf that chains to the CA and honors its constraints", func() {
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			signed, err := client.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{
				KeyID: keyID, Cert: leaf("svc.example.internal"), Parent: parent, PublicKey: key.Public(),
			})
			Expect(err).To(BeNil())
			roots := x509.NewCertPool()
			roots.AddCert(parent)
			_, err = signed.Verify(x509.VerifyOptions{Roots: roots, DNSName: "svc.example.internal"})
			Expect(err).To(BeNil())

			By("checking a name outside the constraints fails verification even if signed")
			outside, err := client.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{
				KeyID: keyID, Cert: leaf("accounts.google.com"), Parent: parent, PublicKey: key.Public(),
			})
			Expect(err).To(BeNil())
			_, err = outside.Verify(x509.VerifyOptions{Roots: roots, DNSName: "accounts.google.com"})
			Expect(err).NotTo(BeNil())
		})

		It("should refuse a parent certificate that is not for the KMS key", func() {
			otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			forged := *parent
			forged.PublicKey = otherKey.Public()
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			_, err := client.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{
				KeyID: keyID, Cert: leaf("svc.example.internal"), Parent: &forged, PublicKey: key.Public(),
			})
			Expect(err).NotTo(BeNil())
		})

		It("should refuse a parent that is not a CA", func() {
			notCA := *parent
			notCA.IsCA = false
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			_, err := client.SignCertificate(context.TODO(), &kmsca.IssueCertificateInput{
				KeyID: keyID, Cert: leaf("svc.example.internal"), Parent: &notCA, PublicKey: key.Public(),
			})
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
