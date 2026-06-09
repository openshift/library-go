package encryptionstatus

import (
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func TestWriteKeyNeedsKEKRemigration(t *testing.T) {
	writeKey := state.KeyState{Mode: state.KMS, Migrated: state.MigrationState{KEKID: "kek-a"}}

	if WriteKeyNeedsKEKRemigration(writeKey, "kek-a") {
		t.Fatal("expected no remigration when kekId matches")
	}
	if !WriteKeyNeedsKEKRemigration(writeKey, "kek-b") {
		t.Fatal("expected remigration when kekId differs")
	}
	if WriteKeyNeedsKEKRemigration(writeKey, "") {
		t.Fatal("expected no remigration when kekId is not converged")
	}
	if WriteKeyNeedsKEKRemigration(state.KeyState{Mode: state.AESCBC}, "kek-b") {
		t.Fatal("expected no remigration for non-KMS keys")
	}
}
