package certmanager

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/kms"

	mocks "github.com/sunsofterp/kms-issuer/v5/pkg/kmsmock"
)

// failingKMS is the mock with GetPublicKey and Sign failing, like a KMS outage.
type failingKMS struct {
	*mocks.KMSMock
}

var errKMSDown = errors.New("mock: KMS unavailable")

func (failingKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return nil, errKMSDown
}

func (failingKMS) Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) {
	return nil, errKMSDown
}
