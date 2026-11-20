package creator

import (
	"context"

	"github.com/openshift/library-go/pkg/crypto"
)

type KeyPairGeneratorGetter interface {
	GetKeyPairGenerator() (crypto.KeyPairGenerator, error)
}

type SignerGetter interface {
	GetSigner(context.Context) (*crypto.CA, error)
}
