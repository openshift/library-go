package secrets

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	v1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/utils/diff"
	sigyaml "sigs.k8s.io/yaml"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func TestRoundtrip(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	emptyKey := make([]byte, 16)

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
			name:      "full kms",
			component: "kms",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "1",
					Secret: base64.StdEncoding.EncodeToString(emptyKey),
				},
				Backed: true,
				Mode:   "KMS",
				KMS: &state.KMSConfig{
					EncryptionConfig: &v1.KMSConfiguration{
						APIVersion: "v2",
						Name:       "1",
						Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
					},
					ProviderConfig: &state.KMSProviderConfig{
						KMSConfig: &configv1.KMSConfig{
							Type: configv1.VaultKMSProvider,
							Vault: configv1.VaultKMSConfig{
								KMSPluginImage: "quay.io/openshift/kms-plugin:latest",
								VaultAddress:   "https://vault.example.com",
								VaultNamespace: "my-namespace",
								TransitMount:   "transit",
								TransitKey:     "my-key",
							},
						},
					},
				},
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
			name:      "sparse kms",
			component: "kms",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "2",
					Secret: base64.StdEncoding.EncodeToString(emptyKey),
				},
				Backed: true,
				Mode:   "KMS",
				KMS: &state.KMSConfig{
					EncryptionConfig: &v1.KMSConfiguration{
						APIVersion: "v2",
						Name:       "2",
						Endpoint:   "unix:///var/run/kmsplugin/kms-2.sock",
					},
					ProviderConfig: &state.KMSProviderConfig{
						KMSConfig: &configv1.KMSConfig{
							Type: configv1.VaultKMSProvider,
							Vault: configv1.VaultKMSConfig{
								KMSPluginImage: "quay.io/openshift/kms-plugin:latest",
								VaultAddress:   "https://vault.example.com",
								VaultNamespace: "my-namespace",
								TransitMount:   "transit",
								TransitKey:     "my-key",
							},
						},
					},
				},
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

func TestFromKeyStateKMSSecretGolden(t *testing.T) {
	update := os.Getenv("UPDATE_GOLDEN") != ""
	emptyKey := make([]byte, 16)

	tests := []struct {
		name       string
		goldenFile string
		component  string
		ks         state.KeyState
	}{
		{
			name:       "vault kms with all fields",
			goldenFile: "kms-vault-all-fields.yaml",
			component:  "openshift-kube-apiserver",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "1",
					Secret: base64.StdEncoding.EncodeToString(emptyKey),
				},
				Mode: state.KMS,
				KMS: &state.KMSConfig{
					EncryptionConfig: &v1.KMSConfiguration{
						APIVersion: "v2",
						Name:       "1",
						Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
					},
					ProviderConfig: &state.KMSProviderConfig{
						KMSConfig: &configv1.KMSConfig{
							Type: configv1.VaultKMSProvider,
							Vault: configv1.VaultKMSConfig{
								KMSPluginImage: "quay.io/openshift/kms-plugin@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
								VaultAddress:   "https://vault.example.com:8200",
								VaultNamespace: "my-namespace",
								TransitMount:   "transit",
								TransitKey:     "my-key",
								ApproleSecret:  configv1.VaultSecretReference{Name: "vault-approle"},
								TLS: configv1.VaultTLSConfig{
									CABundle:   configv1.VaultConfigMapReference{Name: "vault-ca-bundle"},
									ServerName: "vault.example.com",
								},
							},
						},
					},
				},
				InternalReason: "kms-key-rotation",
				ExternalReason: "user-requested",
			},
		},
		{
			name:       "vault kms minimal",
			goldenFile: "kms-vault-minimal.yaml",
			component:  "openshift-kube-apiserver",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "1",
					Secret: base64.StdEncoding.EncodeToString(emptyKey),
				},
				Mode: state.KMS,
				KMS: &state.KMSConfig{
					EncryptionConfig: &v1.KMSConfiguration{
						APIVersion: "v2",
						Name:       "1",
						Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
					},
					ProviderConfig: &state.KMSProviderConfig{
						KMSConfig: &configv1.KMSConfig{
							Type: configv1.VaultKMSProvider,
							Vault: configv1.VaultKMSConfig{
								KMSPluginImage: "quay.io/openshift/kms-plugin@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
								VaultAddress:   "https://vault.example.com",
								TransitKey:     "my-key",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := FromKeyState(tt.component, tt.ks)
			if err != nil {
				t.Fatalf("unexpected FromKeyState() error: %v", err)
			}

			// Build a readable representation that decodes binary data fields
			// so the golden file shows the actual YAML structure, not base64.
			readable := map[string]interface{}{
				"name":        secret.Name,
				"namespace":   secret.Namespace,
				"labels":      secret.Labels,
				"annotations": secret.Annotations,
				"finalizers":  secret.Finalizers,
				"type":        string(secret.Type),
			}

			dataMap := map[string]interface{}{}
			for k, v := range secret.Data {
				if k == EncryptionSecretKMSProviderConfig || k == EncryptionSecretKMSEncryptionConfig {
					var decoded interface{}
					if err := json.Unmarshal(v, &decoded); err != nil {
						t.Fatalf("failed to decode data key %s: %v", k, err)
					}
					dataMap[k] = decoded
				} else {
					dataMap[k] = base64.StdEncoding.EncodeToString(v)
				}
			}
			readable["data"] = dataMap

			got, err := sigyaml.Marshal(readable)
			if err != nil {
				t.Fatalf("failed to marshal secret to YAML: %v", err)
			}

			goldenPath := filepath.Join("testdata", tt.goldenFile)
			if update {
				if err := os.WriteFile(goldenPath, got, 0644); err != nil {
					t.Fatalf("failed to update golden file: %v", err)
				}
				t.Logf("updated golden file %s", goldenPath)
				return
			}

			expected, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("failed to read golden file %s (run with UPDATE_GOLDEN=1 to create): %v", goldenPath, err)
			}

			if !reflect.DeepEqual(got, expected) {
				t.Errorf("secret does not match golden file %s (run with UPDATE_GOLDEN=1 to update):\n%s", goldenPath, diff.StringDiff(string(expected), string(got)))
			}
		})
	}
}
