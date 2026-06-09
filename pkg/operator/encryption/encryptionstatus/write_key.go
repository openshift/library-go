package encryptionstatus

import (
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

// WriteKeyNeedsKEKRemigration reports whether a KMS write key was migrated under a
// different kekId than the one currently converged across nodes.
func WriteKeyNeedsKEKRemigration(writeKey state.KeyState, convergedKEKID string) bool {
	if writeKey.Mode != state.KMS {
		return false
	}
	if convergedKEKID == "" {
		return false
	}
	return writeKey.Migrated.KEKID != convergedKEKID
}
