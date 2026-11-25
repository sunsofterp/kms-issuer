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

// Package kmsmock is an in-memory stand-in for the parts of AWS KMS the issuer
// uses. Each key has its own RSA key pair, so tests can tell keys apart.
package kmsmock

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"

	"github.com/sunsofterp/kms-issuer/v5/pkg/interfaces"
)

// KMSMock Define a simple mock of the KMS client
type KMSMock struct {
	mu      sync.Mutex
	keys    map[string]*kms.CreateKeyInput
	private map[string]*rsa.PrivateKey
	alias   map[string]string
	pending map[string]bool
	// FailCreateAlias makes CreateAlias fail, for testing cleanup.
	FailCreateAlias bool
}

// Ensure KMSMock implements interface
var _ interfaces.KMSClient = &KMSMock{}

// New creates a new KMSMock instance
func New() *KMSMock {
	return &KMSMock{
		keys:    map[string]*kms.CreateKeyInput{},
		private: map[string]*rsa.PrivateKey{},
		alias:   map[string]string{},
		pending: map[string]bool{},
	}
}

// PendingDeletion reports whether ScheduleKeyDeletion was called for keyID.
func (m *KMSMock) PendingDeletion(keyID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending[keyID]
}

// KeyIDs returns the IDs of the keys created.
func (m *KMSMock) KeyIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.keys))
	for id := range m.keys {
		ids = append(ids, id)
	}
	return ids
}

// CreateKey mocks of the KMS CreateKey method: a new RSA 2048 key pair.
func (m *KMSMock) CreateKey(_ context.Context, input *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	uid := uuid.New().String()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[uid] = input
	m.private[uid] = private
	return &kms.CreateKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{
			KeyId: aws.String(uid),
		},
	}, nil
}

// CreateAlias mocks of the KMS CreateAlias method.
func (m *KMSMock) CreateAlias(_ context.Context, input *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailCreateAlias {
		return nil, &kmstypes.LimitExceededException{Message: aws.String("mock: alias creation fails")}
	}
	m.alias[aws.ToString(input.AliasName)] = aws.ToString(input.TargetKeyId)
	return &kms.CreateAliasOutput{}, nil
}

// DeleteAlias mocks of the KMS DeleteAlias method.
func (m *KMSMock) DeleteAlias(_ context.Context, input *kms.DeleteAliasInput, _ ...func(*kms.Options)) (*kms.DeleteAliasOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.alias, aws.ToString(input.AliasName))
	return &kms.DeleteAliasOutput{}, nil
}

// resolve returns the key ID for a key ID or alias, or "" if unknown. Callers hold mu.
func (m *KMSMock) resolve(id string) string {
	if strings.HasPrefix(id, "alias/") {
		id = m.alias[id]
	}
	if _, ok := m.keys[id]; !ok {
		return ""
	}
	return id
}

// DescribeKey mocks of the KMS DescribeKey method.
func (m *KMSMock) DescribeKey(_ context.Context, input *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keyID := m.resolve(aws.ToString(input.KeyId))
	if keyID == "" {
		return nil, &kmstypes.NotFoundException{}
	}
	state := kmstypes.KeyStateEnabled
	if m.pending[keyID] {
		state = kmstypes.KeyStatePendingDeletion
	}
	return &kms.DescribeKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{
			KeyId:    aws.String(keyID),
			KeyState: state,
		},
	}, nil
}

// ListResourceTags mocks of the KMS ListResourceTags method.
func (m *KMSMock) ListResourceTags(_ context.Context, input *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key, ok := m.keys[aws.ToString(input.KeyId)]; ok {
		return &kms.ListResourceTagsOutput{Tags: key.Tags}, nil
	}
	return nil, &kmstypes.NotFoundException{}
}

// ScheduleKeyDeletion mocks of the KMS ScheduleKeyDeletion method.
func (m *KMSMock) ScheduleKeyDeletion(_ context.Context, input *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keyID := aws.ToString(input.KeyId)
	if _, ok := m.keys[keyID]; !ok {
		return nil, &kmstypes.NotFoundException{}
	}
	if m.pending[keyID] {
		return nil, &kmstypes.KMSInvalidStateException{Message: aws.String("mock: already pending deletion")}
	}
	m.pending[keyID] = true
	return &kms.ScheduleKeyDeletionOutput{}, nil
}

// GetPublicKey mocks of the KMS GetPublicKey method.
func (m *KMSMock) GetPublicKey(_ context.Context, input *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keyID := m.resolve(aws.ToString(input.KeyId))
	if keyID == "" {
		return nil, &kmstypes.NotFoundException{}
	}
	key := m.keys[keyID]
	der, err := x509.MarshalPKIXPublicKey(&m.private[keyID].PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		CustomerMasterKeySpec: kmstypes.CustomerMasterKeySpec(key.KeySpec),
		KeySpec:               key.KeySpec,
		KeyUsage:              key.KeyUsage,
		PublicKey:             der,
	}, nil
}

// Sign mocks of the KMS Sign method: RSA PKCS#1 v1.5 over a digest, like KMS, for
// the three hashes KMS offers; anything else is refused.
func (m *KMSMock) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	m.mu.Lock()
	keyID := m.resolve(aws.ToString(input.KeyId))
	private := m.private[keyID]
	m.mu.Unlock()
	if keyID == "" {
		return nil, &kmstypes.NotFoundException{}
	}
	if input.MessageType != kmstypes.MessageTypeDigest {
		return nil, &kmstypes.InvalidKeyUsageException{Message: aws.String("mock signs digests only")}
	}
	var hash crypto.Hash
	switch input.SigningAlgorithm {
	case kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		hash = crypto.SHA256
	case kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		hash = crypto.SHA384
	case kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		hash = crypto.SHA512
	default:
		return nil, &kmstypes.InvalidKeyUsageException{Message: aws.String("mock does not support " + string(input.SigningAlgorithm))}
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, hash, input.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: signature}, nil
}
