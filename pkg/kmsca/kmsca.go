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

// OwnerTag is the KMS key tag naming the KMSKey (by UID) that created the key. It is
// the only proof of ownership: a key without it, or with another UID, is never
// adopted or deleted.
const OwnerTag = "kms-issuer.cert-manager.skyscanner.net/kmskey-uid"

// ErrAliasTaken is returned when an alias already points at a key the caller did
// not create.
var ErrAliasTaken = errors.New("the alias already points at a key this KMSKey did not create; refusing to adopt it")

// ErrNotOwned is returned by DeleteKey when the alias points at a key this KMSKey
// did not create: nothing is deleted.
var ErrNotOwned = errors.New("the alias points at a key this KMSKey did not create; not deleting it")

// CreateKey creates an asymmetric KMS key used to sign certificates, tagged with its
// owner's UID, and an alias pointing at it. If the alias already exists, its key must
// carry this owner's tag (a previous run created it); any other key is refused. If
// the alias cannot be created, the new key is scheduled for deletion again rather
// than left behind. Returns the key ID.
func (ca *KMSCA) CreateKey(ctx context.Context, input *CreateKeyInput) (string, error) {
	if err := validateAlias(input.AliasName); err != nil {
		return "", err
	}
	if input.OwnerUID == "" {
		return "", errors.New("an owner UID is required")
	}
	existing, found, err := ca.describeAlias(ctx, input.AliasName)
	if err != nil {
		return "", err
	}
	if found {
		owned, err := ca.ownedBy(ctx, existing, input.OwnerUID)
		if err != nil {
			return "", err
		}
		if !owned {
			return "", ErrAliasTaken
		}
		return existing, nil
	}

	keyInput := &kms.CreateKeyInput{
		KeyUsage: kmstypes.KeyUsageTypeSignVerify,
		KeySpec:  kmstypes.KeySpecRsa3072,
		Tags:     []kmstypes.Tag{{TagKey: aws.String(OwnerTag), TagValue: aws.String(input.OwnerUID)}},
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
		if k == OwnerTag {
			continue
		}
		keyInput.Tags = append(keyInput.Tags, kmstypes.Tag{TagKey: aws.String(k), TagValue: aws.String(v)})
	}
	key, err := ca.Client.CreateKey(ctx, keyInput)
	if err != nil {
		return "", err
	}
	keyID := aws.ToString(key.KeyMetadata.KeyId)
	if _, err = ca.Client.CreateAlias(ctx, &kms.CreateAliasInput{
		TargetKeyId: aws.String(keyID),
		AliasName:   aws.String(input.AliasName),
	}); err != nil {
		// Don't leave an unreferenced key behind; the next attempt makes a new one.
		_, cleanupErr := ca.Client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId: aws.String(keyID), PendingWindowInDays: aws.Int32(7),
		})
		return "", errors.Join(fmt.Errorf("creating alias %s: %w", input.AliasName, err), cleanupErr)
	}
	return keyID, nil
}

// DeleteKey schedules deletion of the key behind the alias and deletes the alias,
// only when that key carries this owner's tag. A missing alias means there is
// nothing left to delete. A key already pending deletion is not scheduled again,
// so a retry after a partial failure completes.
func (ca *KMSCA) DeleteKey(ctx context.Context, input *DeleteKeyInput) error {
	if err := validateAlias(input.AliasName); err != nil {
		return err
	}
	if input.OwnerUID == "" {
		return errors.New("an owner UID is required")
	}
	keyID, found, err := ca.describeAlias(ctx, input.AliasName)
	if err != nil || !found {
		return err
	}
	owned, err := ca.ownedBy(ctx, keyID, input.OwnerUID)
	if err != nil {
		return err
	}
	if !owned {
		return ErrNotOwned
	}
	described, err := ca.Client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return err
	}
	if described.KeyMetadata.KeyState != kmstypes.KeyStatePendingDeletion {
		deleteInput := &kms.ScheduleKeyDeletionInput{KeyId: aws.String(keyID)}
		if input.PendingWindowInDays >= 7 && input.PendingWindowInDays <= 30 {
			deleteInput.PendingWindowInDays = aws.Int32(int32(input.PendingWindowInDays)) //nolint:gosec // G115: bounded to 7-30 just above
		}
		if _, err := ca.Client.ScheduleKeyDeletion(ctx, deleteInput); err != nil {
			return err
		}
	}
	_, err = ca.Client.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: aws.String(input.AliasName)})
	return err
}

// describeAlias returns the key ID an alias points at, and whether it exists.
func (ca *KMSCA) describeAlias(ctx context.Context, alias string) (string, bool, error) {
	response, err := ca.Client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(alias)})
	if err != nil {
		var nsk *kmstypes.NotFoundException
		if errors.As(err, &nsk) {
			return "", false, nil
		}
		return "", false, err
	}
	return aws.ToString(response.KeyMetadata.KeyId), true, nil
}

// ownedBy reports whether keyID carries the owner tag with uid.
func (ca *KMSCA) ownedBy(ctx context.Context, keyID, uid string) (bool, error) {
	input := &kms.ListResourceTagsInput{KeyId: aws.String(keyID)}
	for {
		out, err := ca.Client.ListResourceTags(ctx, input)
		if err != nil {
			return false, err
		}
		for _, t := range out.Tags {
			if aws.ToString(t.TagKey) == OwnerTag {
				return aws.ToString(t.TagValue) == uid, nil
			}
		}
		if !out.Truncated || out.NextMarker == nil {
			return false, nil
		}
		input.Marker = out.NextMarker
	}
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
	// OwnerUID is the creating KMSKey's UID, tagged on the key as proof of ownership.
	OwnerUID string
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
	// OwnerUID is the KMSKey's UID: only a key tagged with it is deleted.
	OwnerUID string
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
