package parallel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/verify/store"
	"github.com/openshift/library-go/pkg/verify/store/memory"
)

// delay wraps a store and introduces a delay before each callback.
type delay struct {
	store store.Store
	delay time.Duration
}

// Signatures fetches signatures for the provided digest.
func (s *delay) Signatures(ctx context.Context, name string, digest string, fn store.Callback) error {
	nestedCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	responses := make(chan *signatureResponse, 1)
	go func(ctx context.Context, name string, digest string, responses chan *signatureResponse) {
		err := s.store.Signatures(ctx, name, digest, func(ctx context.Context, signature []byte, errIn error) (done bool, err error) {
			select {
			case <-ctx.Done():
				return true, nil
			case responses <- &signatureResponse{signature: signature, errIn: errIn}:
				log.Printf("queued response: %s", string(signature))
			}
			return false, nil
		})
		if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
			log.Fatal(err)
		}
		select {
		case <-ctx.Done():
		case responses <- nil:
		}
		close(responses)
		return
	}(nestedCtx, name, digest, responses)

	for {
		time.Sleep(s.delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case response := <-responses:
			if response == nil {
				return nil
			}
			log.Printf("sent response: %s", string(response.signature))
			done, err := fn(ctx, response.signature, response.errIn)
			if done || err != nil {
				return err
			}
		}
	}
}

// String returns a description of where this store finds
// signatures.
func (s *delay) String() string {
	return fmt.Sprintf("delay signature store wrapping %s with a delay of %s", s.store, s.delay)
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	parallel := &Store{
		Stores: []store.Store{
			&delay{
				store: &memory.Store{
					Data: map[string][][]byte{
						"sha256:123": {
							[]byte("store-1-sig-1"),
							[]byte("store-1-sig-2"),
						},
					},
				},
				delay: 200 * time.Millisecond,
			},
			&delay{
				store: &memory.Store{
					Data: map[string][][]byte{
						"sha256:123": {
							[]byte("store-2-sig-1"),
							[]byte("store-2-sig-2"),
						},
					},
				},
				delay: 300 * time.Millisecond,
			},
		},
	}

	for _, testCase := range []struct {
		name               string
		doneSignature      string
		doneError          error
		expectedSignatures []string
		expectedError      *regexp.Regexp
	}{
		{
			name: "all",
			expectedSignatures: []string{
				"store-1-sig-1", // 200 ms
				"store-2-sig-1", // 300 ms
				"store-1-sig-2", // 400 ms
				"store-2-sig-2", // 600 ms
			},
		},
		{
			name:          "done early",
			doneSignature: "store-1-sig-2",
			expectedSignatures: []string{
				"store-1-sig-1",
				"store-2-sig-1",
				"store-1-sig-2",
			},
		},
		{
			name:          "error early",
			doneSignature: "store-1-sig-2",
			doneError:     errors.New("test error"),
			expectedSignatures: []string{
				"store-1-sig-1",
				"store-2-sig-1",
				"store-1-sig-2",
			},
			expectedError: regexp.MustCompile("^test error$"),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			signatures := []string{}
			err := parallel.Signatures(ctx, "name", "sha256:123", func(ctx context.Context, signature []byte, errIn error) (done bool, err error) {
				if errIn != nil {
					return false, errIn
				}
				signatures = append(signatures, string(signature))
				if string(signature) == testCase.doneSignature {
					return true, testCase.doneError
				}
				return false, nil
			})
			if err == nil {
				if testCase.expectedError != nil {
					t.Fatalf("signatures succeeded when we expected %s", testCase.expectedError)
				}
			} else if testCase.expectedError == nil {
				t.Fatalf("signatures failed when we expected success: %v", err)
			} else if !testCase.expectedError.MatchString(err.Error()) {
				t.Fatalf("signatures failed with %v (expected %s)", err, testCase.expectedError)
			}

			if !reflect.DeepEqual(signatures, testCase.expectedSignatures) {
				t.Fatalf("signatures gathered %v when we expected %v", signatures, testCase.expectedSignatures)
			}
		})
	}
}
