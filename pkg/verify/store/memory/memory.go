// Package memory implements an in-memory signature store.  This is
// mostly useful for testing.
package memory

import (
	"context"

	"github.com/openshift/library-go/pkg/verify/store"
)

// Store provides access to signatures stored in memory.
type Store struct {
	// Data maps digests to slices of signatures.
	Data map[string][][]byte
}

// Signatures fetches signatures for the provided digest.
func (s *Store) Signatures(ctx context.Context, name string, digest string, fn store.Callback) error {
	for _, signature := range s.Data[digest] {
		done, err := fn(ctx, signature, nil)
		if err != nil || done {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	return nil
}

// String returns a description of where this store finds
// signatures.
func (s *Store) String() string {
	return "in-memory signature store"
}
