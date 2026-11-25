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

package kmsca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/sunsofterp/kms-issuer/v5/pkg/interfaces"
	"github.com/sunsofterp/kms-issuer/v5/pkg/signer"
)

const (
	// clockSkew backdates every certificate's notBefore, for clients whose clocks
	// run slightly behind.
	clockSkew = 5 * time.Minute
	// serialBits is the size of random serial numbers: 127 bits, so the DER encoding
	// is at most 16 octets plus sign, well inside RFC 5280's 20-octet limit.
	serialBits = 127
)

// KMSCA KMS Certificate Authority provides the API operation methods for implementation
// a certificate authority on top of AWS KMS.
type KMSCA struct {
	Client interfaces.KMSClient
}

// NewKMSCA creates a new instance of the KMSCA client with a session.
func NewKMSCA(cfg *aws.Config) *KMSCA {
	return &KMSCA{
		Client: kms.NewFromConfig(*cfg),
	}
}

// ErrAliasTaken is returned when an alias already points at a key the caller did
// not create.
var ErrAliasTaken = errors.New("the alias already points at a key this KMSKey did not create; refusing to adopt it")

// CreateKey creates an asymmetric KMS key used to sign certificates and an alias
// pointing at it. If the alias already exists it must point at input.OwnedKeyID (the
// key a previous run of this KMSKey created); any other existing key is refused.
// Returns the key ID.
func (ca *KMSCA) CreateKey(ctx context.Context, input *CreateKeyInput) (string, error) {
	if err := validateAlias(input.AliasName); err != nil {
		return "", err
	}
	response, err := ca.Client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(input.AliasName),
	})
	if err == nil {
		existing := aws.ToString(response.KeyMetadata.KeyId)
		if input.OwnedKeyID != "" && existing == input.OwnedKeyID {
			return existing, nil
		}
		return "", ErrAliasTaken
	}
	var nsk *kmstypes.NotFoundException
	if !errors.As(err, &nsk) {
		return "", err
	}

	keyInput := &kms.CreateKeyInput{
		KeyUsage: kmstypes.KeyUsageTypeSignVerify,
		KeySpec:  kmstypes.KeySpecRsa3072,
	}
	if input.CustomerMasterKeySpec != "" {
		keyInput.KeySpec = kmstypes.KeySpec(input.CustomerMasterKeySpec)
	}
	if input.Description != "" {
		keyInput.Description = aws.String(input.Description)
	}
	if input.Policy != "" {
		keyInput.Policy = aws.String(input.Policy)
	}
	for k, v := range input.Tags {
		keyInput.Tags = append(keyInput.Tags, kmstypes.Tag{TagKey: aws.String(k), TagValue: aws.String(v)})
	}
	key, err := ca.Client.CreateKey(ctx, keyInput)
	if err != nil {
		return "", err
	}
	_, err = ca.Client.CreateAlias(ctx, &kms.CreateAliasInput{
		TargetKeyId: key.KeyMetadata.KeyId,
		AliasName:   aws.String(input.AliasName),
	})
	if err != nil {
		return "", err
	}
	return aws.ToString(key.KeyMetadata.KeyId), nil
}

// DeleteKey schedules deletion of the key this KMSKey created (input.OwnedKeyID) and
// deletes its alias. It refuses when the alias now points at any other key.
func (ca *KMSCA) DeleteKey(ctx context.Context, input *DeleteKeyInput) error {
	if err := validateAlias(input.AliasName); err != nil {
		return err
	}
	if input.OwnedKeyID == "" {
		return errors.New("no key was recorded as created by this KMSKey; refusing to delete anything")
	}
	response, err := ca.Client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(input.AliasName),
	})
	if err != nil {
		return err
	}
	if aws.ToString(response.KeyMetadata.KeyId) != input.OwnedKeyID {
		return fmt.Errorf("alias %s points at %s, not the key this KMSKey created (%s); refusing to delete it",
			input.AliasName, aws.ToString(response.KeyMetadata.KeyId), input.OwnedKeyID)
	}
	deleteInput := &kms.ScheduleKeyDeletionInput{
		KeyId: aws.String(input.OwnedKeyID),
	}
	if input.PendingWindowInDays >= 7 && input.PendingWindowInDays <= 30 {
		deleteInput.PendingWindowInDays = aws.Int32(int32(input.PendingWindowInDays)) //nolint:gosec // G115: bounded to 7-30 just above
	}
	if _, err := ca.Client.ScheduleKeyDeletion(ctx, deleteInput); err != nil {
		return err
	}
	_, err = ca.Client.DeleteAlias(ctx, &kms.DeleteAliasInput{
		AliasName: aws.String(input.AliasName),
	})
	return err
}

func validateAlias(alias string) error {
	if len(alias) <= len("alias/") || alias[:len("alias/")] != "alias/" {
		return fmt.Errorf("%q is not an alias name (alias/...)", alias)
	}
	return nil
}

// RandomSerial returns a positive random serial number of serialBits bits.
func RandomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

// CertificateAuthorityTemplate returns the CA certificate template: a root with
// path length 0 (it can sign leaves only) and critical name constraints limiting
// every name under it to input.PermittedDNSDomains.
func CertificateAuthorityTemplate(input *GenerateCertificateAuthorityCertificateInput) (*x509.Certificate, error) {
	if len(input.PermittedDNSDomains) == 0 {
		return nil, errors.New("a CA certificate needs at least one permitted DNS domain")
	}
	serial, err := RandomSerial()
	if err != nil {
		return nil, err
	}
	notBefore := input.Now.Add(-clockSkew).UTC().Truncate(time.Second)
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               input.Subject,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(input.Duration),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// Every name of every type under this CA must be in the permitted domains:
		// DNS names, URI hosts and email domains are limited to them, and no IP
		// address is permitted at all.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         input.PermittedDNSDomains,
		PermittedURIDomains:         input.PermittedDNSDomains,
		PermittedEmailAddresses:     input.PermittedDNSDomains,
		ExcludedIPRanges:            allIPRanges(),
	}, nil
}

// GenerateAndSignCertificateAuthorityCertificate makes and self-signs the CA
// certificate with the KMS key.
func (ca *KMSCA) GenerateAndSignCertificateAuthorityCertificate(ctx context.Context, input *GenerateCertificateAuthorityCertificateInput) (*x509.Certificate, error) {
	cert, err := CertificateAuthorityTemplate(input)
	if err != nil {
		return nil, err
	}
	kmsSigner, err := signer.New(ctx, ca.Client, input.KeyID)
	if err != nil {
		return nil, err
	}
	signedBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, kmsSigner.Public(), kmsSigner)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signedBytes)
}

// PublicKey returns the KMS key's public key.
func (ca *KMSCA) PublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	kmsSigner, err := signer.New(ctx, ca.Client, keyID)
	if err != nil {
		return nil, err
	}
	return kmsSigner.Public(), nil
}

// SignCertificate signs input.Cert with the KMS key, under input.Parent. It refuses
// when Parent is not a CA certificate for that same key (a parent read from a
// tampered status would otherwise produce a certificate naming the wrong issuer).
func (ca *KMSCA) SignCertificate(ctx context.Context, input *IssueCertificateInput) (*x509.Certificate, error) {
	if !input.Parent.IsCA {
		return nil, errors.New("the issuer certificate is not a CA certificate")
	}
	kmsSigner, err := signer.New(ctx, ca.Client, input.KeyID)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(input.Parent.PublicKey, kmsSigner.Public()) {
		return nil, errors.New("the issuer certificate's public key is not the KMS key's")
	}
	signedBytes, err := x509.CreateCertificate(rand.Reader, input.Cert, input.Parent, input.PublicKey, kmsSigner)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signedBytes)
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

// CreateKeyInput input for the CreateKey method
type CreateKeyInput struct {
	// AliasName Specifies the alias name for the kms key. This value must begin with alias/ followed by a
	// name, such as alias/ExampleAlias.
	AliasName string
	// OwnedKeyID is the key a previous run created for this alias, if any.
	OwnedKeyID string
	// Description for the key
	Description string
	// CustomerMasterKeySpec determines the key spec (default RSA_3072).
	CustomerMasterKeySpec string
	// The key policy to attach to the CMK
	Policy string
	// Tags is a list of tags for the key
	Tags map[string]string
}

// DeleteKeyInput input for the DeleteKey method
type DeleteKeyInput struct {
	// AliasName Specifies the alias name for the kms key.
	AliasName string
	// OwnedKeyID is the key this KMSKey created: the only key it will delete.
	OwnedKeyID string
	// PendingWindowInDays, 7 to 30; anything else uses KMS's default of 30.
	PendingWindowInDays int
}

type Key struct {
	// KeyID is the KMS Key Id
	KeyID string
}

type GenerateCertificateAuthorityCertificateInput struct {
	// KeyID is the KMS Key Id
	KeyID string
	// Subject of the CA certificate
	Subject pkix.Name
	// Duration is certificate validity duration
	Duration time.Duration
	// PermittedDNSDomains become the certificate's name constraints.
	PermittedDNSDomains []string
	// Now is the issuance time.
	Now time.Time
}

type IssueCertificateInput struct {
	// KeyID is the KMS Key Id
	KeyID string
	// Cert is the certificate template to sign
	Cert *x509.Certificate
	// PublicKey is the subject's public key
	PublicKey crypto.PublicKey
	// Parent is the issuing CA certificate
	Parent *x509.Certificate
}
