package encoding

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func TestInternalKMSPluginConfigRoundTrip(t *testing.T) {
	original := state.InternalKMSPluginConfig{
		Plugin: configv1.KMSPluginConfig{
			Type: configv1.VaultKMSProvider,
			Vault: configv1.VaultKMSPluginConfig{
				VaultAddress: "https://vault.example.com",
				VaultKeyPath: "transit/keys/my-key",
				Authentication: configv1.VaultAuthentication{
					Type: configv1.VaultAuthenticationTypeAppRole,
					AppRole: configv1.VaultAppRoleAuthentication{
						Secret: configv1.VaultSecretReference{Name: "vault-approle"},
					},
				},
			},
		},
		KMSPluginImage: "registry.example.com/kms-plugin@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	}

	encoded, err := EncodeInternalKMSPluginConfig(original)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	decoded, err := DecodeInternalKMSPluginConfig(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Plugin.Type != original.Plugin.Type {
		t.Errorf("Plugin.Type: got %q, want %q", decoded.Plugin.Type, original.Plugin.Type)
	}
	if decoded.Plugin.Vault.VaultAddress != original.Plugin.Vault.VaultAddress {
		t.Errorf("Plugin.Vault.VaultAddress: got %q, want %q", decoded.Plugin.Vault.VaultAddress, original.Plugin.Vault.VaultAddress)
	}
	if decoded.Plugin.Vault.VaultKeyPath != original.Plugin.Vault.VaultKeyPath {
		t.Errorf("Plugin.Vault.VaultKeyPath: got %q, want %q", decoded.Plugin.Vault.VaultKeyPath, original.Plugin.Vault.VaultKeyPath)
	}
	if decoded.KMSPluginImage != original.KMSPluginImage {
		t.Errorf("KMSPluginImage: got %q, want %q", decoded.KMSPluginImage, original.KMSPluginImage)
	}
}
