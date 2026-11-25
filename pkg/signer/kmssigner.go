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

package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/sunsofterp/kms-issuer/v5/pkg/interfaces"
)

// signTimeout bounds each KMS call (GetPublicKey, Sign).
const signTimeout = 30 * time.Second

// KMSSigner implements crypto.Signer with an AWS KMS asymmetric SIGN_VERIFY key.
// It is meant to live for one signing operation: it carries the context of the
// reconcile that created it, since crypto.Signer has no context of its own.
type KMSSigner struct {
	ctx       context.Context
	client    interfaces.KMSClient
	keyID     string
	publicKey crypto.PublicKey
}

// New returns a KMSSigner for keyID, fetching its public key. ctx bounds every call
// the signer makes.
func New(ctx context.Context, client interfaces.KMSClient, keyID string) (*KMSSigner, error) {
	getCtx, cancel := context.WithTimeout(ctx, signTimeout)
	defer cancel()
	response, err := client.GetPublicKey(getCtx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, err
	}
	if response.KeyUsage != "" && response.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("KMS key %s has usage %s, not SIGN_VERIFY", keyID, response.KeyUsage)
	}
	key, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		return nil, err
	}
	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("KMS key %s has an unsupported public key type %T", keyID, key)
	}
	return &KMSSigner{
		ctx:       ctx,
		client:    client,
		keyID:     keyID,
		publicKey: key,
	}, nil
}

// Public returns the public key corresponding to the opaque, private key.
func (s *KMSSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the KMS key, with the algorithm the key type and opts call
// for. Anything it cannot map to a KMS signing algorithm is refused.
func (s *KMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("signer options are required")
	}
	algorithm, err := signingAlgorithm(s.publicKey, opts)
	if err != nil {
		return nil, err
	}
	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("digest is %d bytes, %s needs %d", len(digest), opts.HashFunc(), opts.HashFunc().Size())
	}
	ctx, cancel := context.WithTimeout(s.ctx, signTimeout)
	defer cancel()
	resp, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: algorithm,
	})
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

// signingAlgorithm maps a public key type and signer options to a KMS algorithm.
func signingAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (kmstypes.SigningAlgorithmSpec, error) {
	_, pss := opts.(*rsa.PSSOptions)
	hash := opts.HashFunc()
	switch pub.(type) {
	case *rsa.PublicKey:
		switch {
		case pss && hash == crypto.SHA256:
			return kmstypes.SigningAlgorithmSpecRsassaPssSha256, nil
		case pss && hash == crypto.SHA384:
			return kmstypes.SigningAlgorithmSpecRsassaPssSha384, nil
		case pss && hash == crypto.SHA512:
			return kmstypes.SigningAlgorithmSpecRsassaPssSha512, nil
		case !pss && hash == crypto.SHA256:
			return kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case !pss && hash == crypto.SHA384:
			return kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case !pss && hash == crypto.SHA512:
			return kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		}
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return kmstypes.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return kmstypes.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return kmstypes.SigningAlgorithmSpecEcdsaSha512, nil
		}
	}
	return "", fmt.Errorf("no KMS signing algorithm for a %T key with %s (PSS: %t)", pub, hash, pss)
}
