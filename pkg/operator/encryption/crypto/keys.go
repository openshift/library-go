package crypto

import (
	"crypto/rand"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

var (
	ModeToNewKeyFunc = map[state.Mode]func() []byte{
		state.AESCBC:    NewAES256Key,
		state.AESGCM:    NewAES256Key,
		state.SecretBox: NewAES256Key, // secretbox requires a 32 byte key so we can reuse the same function here
		state.Identity:  NewIdentityKey,
		state.KMS:       NewIdentityKey, // this is not used in KMS
	}
)

func NewAES256Key() []byte {
	b := make([]byte, 32) // AES-256 == 32 byte key
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand should never fail
	}
	return b
}

func NewIdentityKey() []byte {
	return make([]byte, 16) // the key is not used to perform encryption but must be a valid AES key
}
