package kms

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/stretchr/testify/require"
)

func TestParseKeyIDFromEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		wantKeyID string
		wantErr   string
	}{
		{
			name:      "standard endpoint",
			endpoint:  "unix:///var/run/kmsplugin/kms-555.sock",
			wantKeyID: "555",
		},
		{
			name:      "single digit key ID",
			endpoint:  "unix:///var/run/kmsplugin/kms-3.sock",
			wantKeyID: "3",
		},
		{
			name:     "missing kms- prefix",
			endpoint: "unix:///var/run/kmsplugin/plugin-555.sock",
			wantErr:  "unexpected KMS endpoint format",
		},
		{
			name:     "missing .sock suffix",
			endpoint: "unix:///var/run/kmsplugin/kms-555.socket",
			wantErr:  "unexpected KMS endpoint format",
		},
		{
			name:     "empty key ID",
			endpoint: "unix:///var/run/kmsplugin/kms-.sock",
			wantErr:  "unexpected KMS endpoint format",
		},
		{
			name:     "no unix prefix",
			endpoint: "/var/run/kmsplugin/kms-555.sock",
			wantErr:  "unexpected KMS endpoint format",
		},
		{
			name:     "no digit key ID",
			endpoint: "/var/run/kmsplugin/kms-abc.sock",
			wantErr:  "unexpected KMS endpoint format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, err := ParseKeyIDFromEndpoint(tt.endpoint)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantKeyID, keyID)
		})
	}
}

func TestDecodeEncryptionConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name: "valid EncryptionConfiguration",
			data: []byte(`
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          apiVersion: v2
          name: test
          endpoint: unix:///var/run/kmsplugin/kms-1.sock
          timeout: 10s
      - identity: {}
`),
		},
		{
			name:    "invalid YAML",
			data:    []byte(`not valid yaml: [`),
			wantErr: "failed to decode",
		},
		{
			name:    "wrong kind",
			data:    []byte(`{"apiVersion": "v1", "kind": "Secret"}`),
			wantErr: "failed to decode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := DecodeEncryptionConfiguration(tt.data)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, config)
			require.Len(t, config.Resources, 1)
		})
	}
}

func TestGetKMSProviderConfig(t *testing.T) {
	vaultConfig := &state.KMSProviderConfig{
		Vault: &state.VaultProviderConfig{
			Image:          "quay.io/test/vault:v1",
			VaultAddress:   "https://vault.example.com:8200",
			VaultNamespace: "my-namespace",
			TransitKey:     "my-key",
			TransitMount:   "transit",
		},
	}
	configBytes, err := json.Marshal(vaultConfig)
	require.NoError(t, err)

	providerConfigKey := fmt.Sprintf("%s-%s", secrets.EncryptionSecretKMSProviderConfig, "555")

	tests := []struct {
		name       string
		secretData map[string][]byte
		keyID      string
		wantErr    string
	}{
		{
			name: "valid provider config",
			secretData: map[string][]byte{
				providerConfigKey: configBytes,
			},
			keyID: "555",
		},
		{
			name:       "missing provider config key",
			secretData: map[string][]byte{},
			keyID:      "555",
			wantErr:    "missing provider config key",
		},
		{
			name: "invalid JSON",
			secretData: map[string][]byte{
				providerConfigKey: []byte(`{invalid`),
			},
			keyID:   "555",
			wantErr: "failed to unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := GetKMSProviderConfig(tt.secretData, tt.keyID)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, config)
			require.Equal(t, vaultConfig, config)
		})
	}
}
