package creator

import (
	"context"

	"github.com/openshift/library-go/pkg/crypto"
)

// KeyPairGeneratorGetter is used for fetching a crypto.KeyPairGenerator.
// It returns either a crypto.KeyPairGenerator or an error.
// Implementors should never return nil, nil.
type KeyPairGeneratorGetter interface {
	GetKeyPairGenerator(context.Context) (crypto.KeyPairGenerator, error)
}

// SignerGetter is used for fetching a *crypto.CA.
// It returns either a *crypto.CA or an error.
// Implementors should never return nil, nil.
type SignerGetter interface {
	GetSigner(context.Context) (*crypto.CA, error)
}
