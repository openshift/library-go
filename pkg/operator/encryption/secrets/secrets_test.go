package secrets

import (
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	v1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/utils/diff"

	configv1 "github.com/openshift/api/config/v1"

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
				KMSConfiguration: &v1.KMSConfiguration{
					APIVersion: "v2",
					Name:       "1",
					Endpoint:   "unix:///var/run/kmsplugin/kms.sock",
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
				KMSConfiguration: &v1.KMSConfiguration{
					APIVersion: "v2",
					Name:       "2",
					Endpoint:   "unix:///var/run/kmsplugin/kms.sock",
				},
			},
		},
		{
			name:      "kms with provider config stores ec config in data field",
			component: "kms",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "1",
					Secret: base64.StdEncoding.EncodeToString(emptyKey),
				},
				Backed: true,
				Mode:   "KMS",
				KMSConfiguration: &v1.KMSConfiguration{
					APIVersion: "v2",
					Name:       "1",
					Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
				},
				KMSProviderConfig: &configv1.KMSConfig{
					Type: configv1.VaultKMSProvider,
					Vault: &configv1.VaultKMSConfig{
						Image:        "quay.io/org/vault-kms-plugin@sha256:abc123def456789012345678901234567890123456789012345678901234abcd",
						VaultAddress: "https://vault.example.com:8200",
						TransitKey:   "my-key",
						TransitMount: "transit",
					},
				},
			},
		},
		{
			name:      "kms with provider config full roundtrip",
			component: "kms",
			ks: state.KeyState{
				Key: v1.Key{
					Name:   "3",
					Secret: base64.StdEncoding.EncodeToString(emptyKey),
				},
				Backed: true,
				Mode:   "KMS",
				KMSConfiguration: &v1.KMSConfiguration{
					APIVersion: "v2",
					Name:       "3",
					Endpoint:   "unix:///var/run/kmsplugin/kms-3.sock",
				},
				KMSProviderConfig: &configv1.KMSConfig{
					Type: configv1.VaultKMSProvider,
					Vault: &configv1.VaultKMSConfig{
						Image:          "quay.io/org/vault-kms-plugin@sha256:abc123def456789012345678901234567890123456789012345678901234abcd",
						VaultAddress:   "https://vault.example.com:8200",
						TransitKey:     "my-key",
						TransitMount:   "transit",
						VaultNamespace: "admin",
						TLSServerName:  "vault.tls.example.com",
						ApproleSecretRef: configv1.SecretNameReference{
							Name: "vault-approle",
						},
					},
				},
				Migrated: state.MigrationState{
					Timestamp: now,
					Resources: []schema.GroupResource{
						{Resource: "secrets"},
					},
				},
				InternalReason: "kms-configuration-changed",
				ExternalReason: "",
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
