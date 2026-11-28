package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestSigningAlgorithm(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	ok := []struct {
		pub  crypto.PublicKey
		opts crypto.SignerOpts
		want kmstypes.SigningAlgorithmSpec
	}{
		{&rsaKey.PublicKey, crypto.SHA256, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256},
		{&rsaKey.PublicKey, crypto.SHA384, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384},
		{&rsaKey.PublicKey, crypto.SHA512, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512},
		{&rsaKey.PublicKey, &rsa.PSSOptions{Hash: crypto.SHA256}, kmstypes.SigningAlgorithmSpecRsassaPssSha256},
		{&ecKey.PublicKey, crypto.SHA256, kmstypes.SigningAlgorithmSpecEcdsaSha256},
		{&ecKey.PublicKey, crypto.SHA384, kmstypes.SigningAlgorithmSpecEcdsaSha384},
	}
	for _, tc := range ok {
		got, err := signingAlgorithm(tc.pub, tc.opts)
		if err != nil || got != tc.want {
			t.Errorf("signingAlgorithm(%T, %v) = %s, %v; want %s", tc.pub, tc.opts, got, err, tc.want)
		}
	}

	refused := []struct {
		pub  crypto.PublicKey
		opts crypto.SignerOpts
	}{
		{&rsaKey.PublicKey, crypto.SHA1},
		{&rsaKey.PublicKey, crypto.MD5},
		{&ecKey.PublicKey, crypto.SHA1},
		{edPub, crypto.Hash(0)},
	}
	for _, tc := range refused {
		if got, err := signingAlgorithm(tc.pub, tc.opts); err == nil {
			t.Errorf("signingAlgorithm(%T, %v) = %s; want refused", tc.pub, tc.opts, got)
		}
	}
}

func TestSignRefusesWrongDigestLength(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := &KMSSigner{publicKey: &rsaKey.PublicKey}
	if _, err := s.Sign(nil, make([]byte, 20), crypto.SHA256); err == nil {
		t.Error("signed a 20-byte digest as SHA-256")
	}
	if _, err := s.Sign(nil, make([]byte, 32), nil); err == nil {
		t.Error("signed with no options")
	}
}
