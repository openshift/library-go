package serial

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"testing"

	"github.com/openshift/library-go/pkg/verify/store"
	"github.com/openshift/library-go/pkg/verify/store/memory"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	serial := &Store{
		Stores: []store.Store{
			&memory.Store{
				Data: map[string][][]byte{
					"sha256:123": {
						[]byte("store-1-sig-1"),
						[]byte("store-1-sig-2"),
					},
				},
			},
			&memory.Store{
				Data: map[string][][]byte{
					"sha256:123": {
						[]byte("store-2-sig-1"),
						[]byte("store-2-sig-2"),
					},
				},
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
				"store-1-sig-1",
				"store-1-sig-2",
				"store-2-sig-1",
				"store-2-sig-2",
			},
		},
		{
			name:          "done early",
			doneSignature: "store-2-sig-1",
			expectedSignatures: []string{
				"store-1-sig-1",
				"store-1-sig-2",
				"store-2-sig-1",
			},
		},
		{
			name:          "error early",
			doneSignature: "store-2-sig-1",
			doneError:     errors.New("test error"),
			expectedSignatures: []string{
				"store-1-sig-1",
				"store-1-sig-2",
				"store-2-sig-1",
			},
			expectedError: regexp.MustCompile("^test error$"),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			signatures := []string{}
			err := serial.Signatures(ctx, "name", "sha256:123", func(ctx context.Context, signature []byte, errIn error) (done bool, err error) {
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
