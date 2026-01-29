package kms

import (
	"encoding/base64"
	"testing"

	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

func TestRoundtrip(t *testing.T) {
	endpoints := []string{
		DefaultEndpoint,
		"unix:///custom/path/kms.sock",
		"unix:///another/path.sock",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			original := NewKMS(endpoint)

			data, err := original.ToBytes()
			if err != nil {
				t.Fatalf("ToBytes() error: %v", err)
			}

			restored, err := FromBytes(data)
			if err != nil {
				t.Fatalf("FromBytes() error: %v", err)
			}

			if restored.Endpoint != original.Endpoint {
				t.Errorf("roundtrip failed: got %q, want %q", restored.Endpoint, original.Endpoint)
			}
		})
	}
}

func TestToProviderName(t *testing.T) {
	tests := []struct {
		name         string
		resourceName string
		key          apiserverconfigv1.Key
		want         string
	}{
		{
			name:         "secrets resource",
			resourceName: "secrets",
			key: apiserverconfigv1.Key{
				Name:   "1",
				Secret: "XUFAKrxLKna5cZnZEQH8Ug==", // # notsecret
			},
			want: "kms-secrets-1-XUFAKrxLKna5cZnZEQH8Ug==",
		},
		{
			name:         "configmaps resource",
			resourceName: "configmaps",
			key: apiserverconfigv1.Key{
				Name:   "2",
				Secret: "abcd1234efgh5678ijkl9012",
			},
			want: "kms-configmaps-2-abcd1234efgh5678ijkl9012",
		},
		{
			name:         "resource with group",
			resourceName: "routes.networking.openshift.io",
			key: apiserverconfigv1.Key{
				Name:   "10",
				Secret: "base64+encoded/secret==",
			},
			want: "kms-routes.networking.openshift.io-10-base64+encoded/secret==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToProviderName(tt.resourceName, tt.key)
			if got != tt.want {
				t.Errorf("ToProviderName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromProviderName(t *testing.T) {
	tests := []struct {
		name         string
		providerName string
		wantKeyID    string
		wantKMSKey   string
		wantErr      bool
	}{
		{
			name:         "valid provider name",
			providerName: "kms-secrets-1-XUFAKrxLKna5cZnZEQH8Ug==",
			wantKeyID:    "1",
			wantKMSKey:   "XUFAKrxLKna5cZnZEQH8Ug==",
			wantErr:      false,
		},
		{
			name:         "valid provider name with different resource",
			providerName: "kms-configmaps-2-abcd1234efgh5678ijkl9012",
			wantKeyID:    "2",
			wantKMSKey:   "abcd1234efgh5678ijkl9012",
			wantErr:      false,
		},
		{
			name:         "valid provider name with resource group",
			providerName: "kms-routes.networking.openshift.io-10-base64+encoded/secret==",
			wantKeyID:    "10",
			wantKMSKey:   "base64+encoded/secret==",
			wantErr:      false,
		},
		{
			name:         "invalid format - missing parts",
			providerName: "kms-secrets-1",
			wantErr:      true,
		},
		{
			name:         "invalid format - not kms prefix",
			providerName: "aescbc-secrets-1-key",
			wantErr:      true,
		},
		{
			name:         "invalid format - empty string",
			providerName: "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKeyID, gotKMSKey, err := FromProviderName(tt.providerName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromProviderName() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if gotKeyID != tt.wantKeyID {
					t.Errorf("FromProviderName() keyID = %q, want %q", gotKeyID, tt.wantKeyID)
				}
				if gotKMSKey != tt.wantKMSKey {
					t.Errorf("FromProviderName() kmsKey = %q, want %q", gotKMSKey, tt.wantKMSKey)
				}
			}
		})
	}
}

func TestProviderNameRoundtrip(t *testing.T) {
	tests := []struct {
		name         string
		resourceName string
		key          apiserverconfigv1.Key
	}{
		{
			name:         "secrets",
			resourceName: "secrets",
			key: apiserverconfigv1.Key{
				Name:   "1",
				Secret: base64.StdEncoding.EncodeToString([]byte("checksum-data")),
			},
		},
		{
			name:         "configmaps",
			resourceName: "configmaps",
			key: apiserverconfigv1.Key{
				Name:   "99",
				Secret: base64.StdEncoding.EncodeToString([]byte("another-checksum")),
			},
		},
		{
			name:         "with special characters in base64",
			resourceName: "routes",
			key: apiserverconfigv1.Key{
				Name:   "42",
				Secret: "abc+def/ghi==", // # notsecret
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create provider name
			providerName := ToProviderName(tt.resourceName, tt.key)

			// Parse it back
			gotKeyID, gotKMSKey, err := FromProviderName(providerName)
			if err != nil {
				t.Fatalf("FromProviderName() error: %v", err)
			}

			// Verify
			if gotKeyID != tt.key.Name {
				t.Errorf("roundtrip keyID = %q, want %q", gotKeyID, tt.key.Name)
			}
			if gotKMSKey != tt.key.Secret {
				t.Errorf("roundtrip kmsKey = %q, want %q", gotKMSKey, tt.key.Secret)
			}
		})
	}
}
