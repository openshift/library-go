package secrets

import (
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	v1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/utils/diff"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func TestRoundtrip(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	tests := []struct {
		name      string
		component string
		ks        state.KeyState
	}{
		{
			name:      "full aescbc",
			component: "kms",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "54",
					Secret: base64.StdEncoding.EncodeToString([]byte("abcdef")),
				},
				Backed: true, // this will be set by ToKeyState()
				Mode:   "aescbc",
				Migrated: state.MigrationState{
					Timestamp: now,
					Resources: []schema.GroupResource{
						{Resource: "secrets"},
						{Resource: "configmaps"},
						{Group: "networking.openshift.io", Resource: "routes"},
					},
				},
				InternalReason: "internal",
				ExternalReason: "external",
			},
		},
		{
			name:      "sparse aescbc",
			component: "kms",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "54",
					Secret: base64.StdEncoding.EncodeToString([]byte("abcdef")),
				},
				Backed: true, // this will be set by ToKeyState()
				Mode:   "aescbc",
			},
		},
		{
			name:      "full aesgcm",
			component: "kms",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "54",
					Secret: base64.StdEncoding.EncodeToString([]byte("abcdef")),
				},
				Backed: true, // this will be set by ToKeyState()
				Mode:   "aesgcm",
				Migrated: state.MigrationState{
					Timestamp: now,
					Resources: []schema.GroupResource{
						{Resource: "secrets"},
						{Resource: "configmaps"},
						{Group: "networking.openshift.io", Resource: "routes"},
					},
				},
				InternalReason: "internal",
				ExternalReason: "external",
			},
		},
		{
			name:      "sparse aesgcm",
			component: "kms",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "54",
					Secret: base64.StdEncoding.EncodeToString([]byte("abcdef")),
				},
				Backed: true, // this will be set by ToKeyState()
				Mode:   "aesgcm",
			},
		},
		{
			name:      "identity",
			component: "kms",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "54",
					Secret: "",
				},
				Backed: true, // this will be set by ToKeyState()
				Mode:   "identity",
				Migrated: state.MigrationState{
					Timestamp: now,
					Resources: []schema.GroupResource{
						{Resource: "secrets"},
						{Resource: "configmaps"},
						{Group: "networking.openshift.io", Resource: "routes"},
					},
				},
				InternalReason: "internal",
				ExternalReason: "external",
			},
		},
		{
			name:      "kms with empty secret data",
			component: "apiserver",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "1",
					Secret: "",
				},
				Backed:         true,
				Mode:           "kms",
				KMSConfigHash:  "2e55e11c0b187f2d",
				KMSKeyIDHash:   "abcdef1234567890",
				InternalReason: "kms-config-changed",
				ExternalReason: "kms-key-rotated",
			},
		},
		{
			name:      "kms with full metadata",
			component: "apiserver",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "2",
					Secret: "",
				},
				Backed:        true,
				Mode:          "kms",
				KMSConfigHash: "3f66f22d1c298e3e",
				KMSKeyIDHash:  "fedcba0987654321",
				Migrated: state.MigrationState{
					Timestamp: now,
					Resources: []schema.GroupResource{
						{Resource: "secrets"},
					},
				},
				InternalReason: "kms-provider-changed",
				ExternalReason: "user-initiated-rotation",
			},
		},
		{
			name:      "kms minimal - only config hash",
			component: "apiserver",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "3",
					Secret: "",
				},
				Backed:        true,
				Mode:          "kms",
				KMSConfigHash: "1a2b3c4d5e6f7890",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := FromKeyState(tt.component, tt.ks)
			if err != nil {
				t.Fatalf("unexpected FromKeyState() error: %v", err)
			}
			got, err := ToKeyState(s)
			if err != nil {
				t.Fatalf("unexpected ToKeyState() error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.ks) {
				t.Errorf("roundtrip error:\n%s", diff.ObjectDiff(tt.ks, got))
			}
		})
	}
}

func TestToKeyState_KMS(t *testing.T) {
	tests := []struct {
		name          string
		secretName    string
		secretData    []byte
		annotations   map[string]string
		wantKeyState  state.KeyState
		wantErr       bool
		errorContains string
	}{
		{
			name:       "valid KMS secret with empty data",
			secretName: "encryption-key-apiserver-1",
			secretData: []byte{},
			annotations: map[string]string{
				encryptionSecretMode:           "kms",
				EncryptionSecretKMSConfigHash:  "2e55e11c0b187f2d",
				EncryptionSecretKMSKeyIDHash:   "abcdef1234567890",
				encryptionSecretInternalReason: "kms-config-changed",
				encryptionSecretExternalReason: "kms-key-rotated",
			},
			wantKeyState: state.KeyState{
				Key: v1.Key{
					Name:   "1",
					Secret: "",
				},
				Backed:         true,
				Mode:           "kms",
				KMSConfigHash:  "2e55e11c0b187f2d",
				KMSKeyIDHash:   "abcdef1234567890",
				InternalReason: "kms-config-changed",
				ExternalReason: "kms-key-rotated",
			},
			wantErr: false,
		},
		{
			name:       "KMS secret without KMS key ID hash (only config hash)",
			secretName: "encryption-key-apiserver-2",
			secretData: []byte{},
			annotations: map[string]string{
				encryptionSecretMode:          "kms",
				EncryptionSecretKMSConfigHash: "3f66f22d1c298e3e",
			},
			wantKeyState: state.KeyState{
				Key: v1.Key{
					Name:   "2",
					Secret: "",
				},
				Backed:        true,
				Mode:          "kms",
				KMSConfigHash: "3f66f22d1c298e3e",
				KMSKeyIDHash:  "",
			},
			wantErr: false,
		},
		{
			name:       "KMS secret with both hashes missing (should still work)",
			secretName: "encryption-key-apiserver-3",
			secretData: []byte{},
			annotations: map[string]string{
				encryptionSecretMode: "kms",
			},
			wantKeyState: state.KeyState{
				Key: v1.Key{
					Name:   "3",
					Secret: "",
				},
				Backed:        true,
				Mode:          "kms",
				KMSConfigHash: "",
				KMSKeyIDHash:  "",
			},
			wantErr: false,
		},
		{
			name:       "invalid mode should fail",
			secretName: "encryption-key-apiserver-4",
			secretData: []byte("some-key"),
			annotations: map[string]string{
				encryptionSecretMode: "invalid-mode",
			},
			wantErr:       true,
			errorContains: "has invalid mode",
		},
		{
			name:       "aescbc with empty data should fail",
			secretName: "encryption-key-apiserver-5",
			secretData: []byte{},
			annotations: map[string]string{
				encryptionSecretMode: "aescbc",
			},
			wantErr:       true,
			errorContains: "must have non-empty key",
		},
		{
			name:       "aesgcm with empty data should fail",
			secretName: "encryption-key-apiserver-6",
			secretData: []byte{},
			annotations: map[string]string{
				encryptionSecretMode: "aesgcm",
			},
			wantErr:       true,
			errorContains: "must have non-empty key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        tt.secretName,
					Namespace:   "openshift-config-managed",
					Annotations: tt.annotations,
				},
				Data: map[string][]byte{
					EncryptionSecretKeyDataKey: tt.secretData,
				},
			}

			got, err := ToKeyState(secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToKeyState() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errorContains != "" && err != nil {
					if !contains(err.Error(), tt.errorContains) {
						t.Errorf("ToKeyState() error = %v, should contain %q", err, tt.errorContains)
					}
				}
				return
			}
			if !reflect.DeepEqual(got, tt.wantKeyState) {
				t.Errorf("ToKeyState() mismatch:\n%s", diff.ObjectDiff(tt.wantKeyState, got))
			}
		})
	}
}

func TestFromKeyState_KMS(t *testing.T) {
	tests := []struct {
		name            string
		component       string
		keyState        state.KeyState
		wantSecretName  string
		wantDataEmpty   bool
		wantAnnotations map[string]string
		wantErr         bool
	}{
		{
			name:      "KMS key state creates secret with annotations",
			component: "apiserver",
			keyState: state.KeyState{
				Key: v1.Key{
					Name:   "1",
					Secret: "",
				},
				Mode:          "kms",
				KMSConfigHash: "2e55e11c0b187f2d",
				KMSKeyIDHash:  "abcdef1234567890",
			},
			wantSecretName: "encryption-key-apiserver-1",
			wantDataEmpty:  true,
			wantAnnotations: map[string]string{
				encryptionSecretMode:          "kms",
				EncryptionSecretKMSConfigHash: "2e55e11c0b187f2d",
				EncryptionSecretKMSKeyIDHash:  "abcdef1234567890",
			},
			wantErr: false,
		},
		{
			name:      "KMS key state with only config hash",
			component: "apiserver",
			keyState: state.KeyState{
				Key: v1.Key{
					Name:   "2",
					Secret: "",
				},
				Mode:          "kms",
				KMSConfigHash: "3f66f22d1c298e3e",
			},
			wantSecretName: "encryption-key-apiserver-2",
			wantDataEmpty:  true,
			wantAnnotations: map[string]string{
				encryptionSecretMode:          "kms",
				EncryptionSecretKMSConfigHash: "3f66f22d1c298e3e",
			},
			wantErr: false,
		},
		{
			name:      "KMS key state without any hashes",
			component: "apiserver",
			keyState: state.KeyState{
				Key: v1.Key{
					Name:   "3",
					Secret: "",
				},
				Mode: "kms",
			},
			wantSecretName: "encryption-key-apiserver-3",
			wantDataEmpty:  true,
			wantAnnotations: map[string]string{
				encryptionSecretMode: "kms",
			},
			wantErr: false,
		},
		{
			name:      "KMS with reasons",
			component: "apiserver",
			keyState: state.KeyState{
				Key: v1.Key{
					Name:   "4",
					Secret: "",
				},
				Mode:           "kms",
				KMSConfigHash:  "1a2b3c4d5e6f7890",
				InternalReason: "kms-provider-changed",
				ExternalReason: "user-rotation",
			},
			wantSecretName: "encryption-key-apiserver-4",
			wantDataEmpty:  true,
			wantAnnotations: map[string]string{
				encryptionSecretMode:           "kms",
				EncryptionSecretKMSConfigHash:  "1a2b3c4d5e6f7890",
				encryptionSecretInternalReason: "kms-provider-changed",
				encryptionSecretExternalReason: "user-rotation",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromKeyState(tt.component, tt.keyState)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromKeyState() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Verify secret name
			if got.Name != tt.wantSecretName {
				t.Errorf("FromKeyState() secret name = %v, want %v", got.Name, tt.wantSecretName)
			}

			// Verify namespace
			if got.Namespace != "openshift-config-managed" {
				t.Errorf("FromKeyState() namespace = %v, want openshift-config-managed", got.Namespace)
			}

			// Verify data is empty for KMS
			dataLen := len(got.Data[EncryptionSecretKeyDataKey])
			if tt.wantDataEmpty && dataLen != 0 {
				t.Errorf("FromKeyState() expected empty data for KMS, got %d bytes", dataLen)
			}

			// Verify annotations
			for k, v := range tt.wantAnnotations {
				if gotV, ok := got.Annotations[k]; !ok {
					t.Errorf("FromKeyState() missing annotation %q", k)
				} else if gotV != v {
					t.Errorf("FromKeyState() annotation %q = %v, want %v", k, gotV, v)
				}
			}

			// Verify mode annotation specifically
			if got.Annotations[encryptionSecretMode] != "kms" {
				t.Errorf("FromKeyState() mode annotation = %v, want kms", got.Annotations[encryptionSecretMode])
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
