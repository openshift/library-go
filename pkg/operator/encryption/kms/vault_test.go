package kms

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestMigrationFieldsChanged(t *testing.T) {
	tests := []struct {
		name     string
		stored   *configv1.KMSConfig
		current  *configv1.KMSConfig
		expected bool
	}{
		{
			name:     "both nil",
			stored:   nil,
			current:  nil,
			expected: false,
		},
		{
			name:   "stored nil, current non-nil",
			stored: nil,
			current: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
			},
			expected: true,
		},
		{
			name: "vault address changed",
			stored: &configv1.KMSConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{VaultAddress: "https://old.vault:8200"},
			},
			current: &configv1.KMSConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{VaultAddress: "https://new.vault:8200"},
			},
			expected: true,
		},
		{
			name: "vault namespace changed",
			stored: &configv1.KMSConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{VaultAddress: "https://vault:8200", VaultNamespace: "ns1"},
			},
			current: &configv1.KMSConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{VaultAddress: "https://vault:8200", VaultNamespace: "ns2"},
			},
			expected: true,
		},
		{
			name: "transit key changed",
			stored: &configv1.KMSConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{VaultAddress: "https://vault:8200", TransitKey: "key1"},
			},
			current: &configv1.KMSConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{VaultAddress: "https://vault:8200", TransitKey: "key2"},
			},
			expected: true,
		},
		{
			name: "transit mount changed",
			stored: &configv1.KMSConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{VaultAddress: "https://vault:8200", TransitMount: "transit"},
			},
			current: &configv1.KMSConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{VaultAddress: "https://vault:8200", TransitMount: "transit2"},
			},
			expected: true,
		},
		{
			name: "only in-place fields changed - no migration",
			stored: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					VaultAddress:  "https://vault:8200",
					TransitKey:    "key1",
					TransitMount:  "transit",
					Image:         "old-image@sha256:abc",
					TLSServerName: "old.vault.com",
				},
			},
			current: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					VaultAddress:  "https://vault:8200",
					TransitKey:    "key1",
					TransitMount:  "transit",
					Image:         "new-image@sha256:def",
					TLSServerName: "new.vault.com",
				},
			},
			expected: false,
		},
		{
			name: "no changes",
			stored: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					VaultAddress: "https://vault:8200",
					TransitKey:   "key1",
				},
			},
			current: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					VaultAddress: "https://vault:8200",
					TransitKey:   "key1",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MigrationFieldsChanged(tt.stored, tt.current)
			if got != tt.expected {
				t.Errorf("MigrationFieldsChanged() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestApplyInPlaceFields(t *testing.T) {
	tests := []struct {
		name            string
		stored          *configv1.KMSConfig
		current         *configv1.KMSConfig
		expectedImage   string
		expectedTLS     string
		expectedAddress string
	}{
		{
			name: "in-place fields updated, migration fields preserved",
			stored: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					VaultAddress:  "https://old.vault:8200",
					TransitKey:    "old-key",
					Image:         "old-image@sha256:aaa",
					TLSServerName: "old.tls.com",
				},
			},
			current: &configv1.KMSConfig{
				Type: configv1.VaultKMSProvider,
				Vault: &configv1.VaultKMSConfig{
					VaultAddress:  "https://new.vault:8200",
					TransitKey:    "new-key",
					Image:         "new-image@sha256:bbb",
					TLSServerName: "new.tls.com",
				},
			},
			expectedImage:   "new-image@sha256:bbb",
			expectedTLS:     "new.tls.com",
			expectedAddress: "https://old.vault:8200", // preserved from stored
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ApplyInPlaceFields(tt.stored, tt.current)
			if result.Vault.Image != tt.expectedImage {
				t.Errorf("Image = %q, want %q", result.Vault.Image, tt.expectedImage)
			}
			if result.Vault.TLSServerName != tt.expectedTLS {
				t.Errorf("TLSServerName = %q, want %q", result.Vault.TLSServerName, tt.expectedTLS)
			}
			if result.Vault.VaultAddress != tt.expectedAddress {
				t.Errorf("VaultAddress = %q, want %q (should be preserved from stored)", result.Vault.VaultAddress, tt.expectedAddress)
			}
			if result.Vault.TransitKey != "old-key" {
				t.Errorf("TransitKey = %q, want %q (should be preserved from stored)", result.Vault.TransitKey, "old-key")
			}
		})
	}
}
