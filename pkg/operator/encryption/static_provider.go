package encryption

import (
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
)

// StaticEncryptionProvider always run the encryption controllers and returns a static list of resources to encrypt
type StaticEncryptionProvider []schema.GroupResource

var _ controllers.Provider = StaticEncryptionProvider{}

func (p StaticEncryptionProvider) EncryptedGRs() []schema.GroupResource {
	return p
}

func (p StaticEncryptionProvider) ShouldRunEncryptionControllers() (bool, error) {
	return true, nil
}
