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

var _ = Context("KMSCA", func() {

	Describe("when calling CreateKey", func() {
		It("should create a new KMS key and a Key Alias", func() {
			client := mockKMSCA()
			keyID, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{
				AliasName:             "alias/test-key",
				Tags:                  map[string]string{"Project": "k8s"},
				Description:           "My test key",
				CustomerMasterKeySpec: "RSA_2048",
				Policy:                "{}",
			})
			Expect(err).To(BeNil())
			Expect(keyID).NotTo(BeEmpty())
		})

		It("should return the key it created before", func() {
			client := mockKMSCA()
			keyID, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/test-key"})
			Expect(err).To(BeNil())
			again, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/test-key", OwnedKeyID: keyID})
			Expect(err).To(BeNil())
			Expect(again).To(Equal(keyID))
		})

		It("should refuse to adopt a key it did not create", func() {
			client := mockKMSCA()
			_, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/someone-elses"})
			Expect(err).To(BeNil())
			_, err = client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/someone-elses"})
			Expect(err).To(MatchError(kmsca.ErrAliasTaken))
		})

		It("should refuse a key ID or ARN in place of an alias", func() {
			client := mockKMSCA()
			_, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "arn:aws:kms:us-east-1:111122223333:key/abc"})
			Expect(err).NotTo(BeNil())
		})
	})

	Describe("when calling DeleteKey", func() {
		It("should delete the key it created and its alias", func() {
			client := mockKMSCA()
			keyID, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/test-key"})
			Expect(err).To(BeNil())

			err = client.DeleteKey(context.TODO(), &kmsca.DeleteKeyInput{AliasName: "alias/test-key", OwnedKeyID: keyID})
			Expect(err).To(BeNil())
			_, err = client.Client.DescribeKey(context.TODO(), &kms.DescribeKeyInput{KeyId: aws.String("alias/test-key")})
			Expect(err).To(BeAssignableToTypeOf(&kmstypes.NotFoundException{}))
		})

		It("should refuse to delete a key it did not create", func() {
			client := mockKMSCA()
			_, err := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/test-key"})
			Expect(err).To(BeNil())
			err = client.DeleteKey(context.TODO(), &kmsca.DeleteKeyInput{AliasName: "alias/test-key", OwnedKeyID: "another-key"})
			Expect(err).NotTo(BeNil())
			err = client.DeleteKey(context.TODO(), &kmsca.DeleteKeyInput{AliasName: "alias/test-key"})
			Expect(err).NotTo(BeNil())
		})
	})

	Describe("the CA certificate", func() {
		It("is a path-length-0 root, name-constrained to its domains, with a random short serial", func() {
			client := mockKMSCA()
			keyID, _ := client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/test-key"})
			now := time.Now()
			ca, err := client.GenerateAndSignCertificateAuthorityCertificate(context.TODO(), &kmsca.GenerateCertificateAuthorityCertificateInput{
				KeyID:               keyID,
				Subject:             pkix.Name{CommonName: "Test CA"},
				Duration:            24 * time.Hour,
				PermittedDNSDomains: []string{"example.internal"},
				Now:                 now,
			})
			Expect(err).To(BeNil())
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

			again, err := client.GenerateAndSignCertificateAuthorityCertificate(context.TODO(), &kmsca.GenerateCertificateAuthorityCertificateInput{
				KeyID: keyID, Subject: pkix.Name{CommonName: "Test CA"}, Duration: 24 * time.Hour,
				PermittedDNSDomains: []string{"example.internal"}, Now: now,
			})
			Expect(err).To(BeNil())
			Expect(again.SerialNumber).NotTo(Equal(ca.SerialNumber))

			roots := x509.NewCertPool()
			roots.AddCert(ca)
			_, err = ca.Verify(x509.VerifyOptions{Roots: roots})
			Expect(err).To(BeNil())
		})

		It("needs a permitted domain", func() {
			_, err := kmsca.CertificateAuthorityTemplate(&kmsca.GenerateCertificateAuthorityCertificateInput{Duration: time.Hour, Now: time.Now()})
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
			keyID, _ = client.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/test-key"})
			var err error
			parent, err = client.GenerateAndSignCertificateAuthorityCertificate(context.TODO(), &kmsca.GenerateCertificateAuthorityCertificateInput{
				KeyID: keyID, Subject: pkix.Name{CommonName: "Test CA"}, Duration: 24 * time.Hour,
				PermittedDNSDomains: []string{"example.internal"}, Now: time.Now(),
			})
			Expect(err).To(BeNil())
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
