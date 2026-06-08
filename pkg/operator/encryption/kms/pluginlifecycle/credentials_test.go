package pluginlifecycle

import (
	"path/filepath"
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/stretchr/testify/require"
)

func TestCredentialResolver_Value(t *testing.T) {
	const keyID = "42"
	pluginsSecretData := newTestPluginsSecretData(t, keyID, "my-role-id", "my-secret-id")

	tests := []struct {
		name       string
		keyID      string
		secretName string
		dataKey    string
		expected   string
		expectErr  string
	}{
		{
			name:       "returns stored value",
			keyID:      keyID,
			secretName: "vault-approle",
			dataKey:    "role-id",
			expected:   "my-role-id",
		},
		{
			name:       "missing keyID",
			keyID:      "unknown",
			secretName: "vault-approle",
			dataKey:    "role-id",
			expectErr:  "missing secret data for keyID unknown",
		},
		{
			name:       "missing data key",
			keyID:      keyID,
			secretName: "vault-approle",
			dataKey:    "nonexistent",
			expectErr:  "missing nonexistent in secret vault-approle for keyID 42",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &credentialResolver{
				keyID:             tc.keyID,
				pluginsSecretData: pluginsSecretData,
			}

			got, err := r.Value(tc.secretName, tc.dataKey)
			if tc.expectErr != "" {
				require.EqualError(t, err, tc.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestCredentialResolver_FilePath(t *testing.T) {
	const keyID = "42"
	const credentialsDir = "/etc/kubernetes/static-pod-resources/secrets/encryption-config"

	pluginsSecretData := newTestPluginsSecretData(t, keyID, "my-role-id", "my-secret-id")

	tests := []struct {
		name       string
		keyID      string
		secretName string
		dataKey    string
		expected   string
		expectErr  string
	}{
		{
			name:       "returns correct path",
			keyID:      keyID,
			secretName: "vault-approle",
			dataKey:    "secret-id",
			expected:   filepath.Join(credentialsDir, encryptiondata.FormatKMSSecretDataKey("vault-approle_secret-id", keyID)),
		},
		{
			name:       "missing keyID",
			keyID:      "unknown",
			secretName: "vault-approle",
			dataKey:    "secret-id",
			expectErr:  "missing secret data for keyID unknown",
		},
		{
			name:       "missing data key",
			keyID:      keyID,
			secretName: "vault-approle",
			dataKey:    "nonexistent",
			expectErr:  "missing nonexistent in secret vault-approle for keyID 42",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &credentialResolver{
				keyID:             tc.keyID,
				credentialsDir:    credentialsDir,
				pluginsSecretData: pluginsSecretData,
			}

			got, err := r.FilePath(tc.secretName, tc.dataKey)
			if tc.expectErr != "" {
				require.EqualError(t, err, tc.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func newTestPluginsSecretData(t *testing.T, keyID, roleID, secretID string) encryptiondata.KMSPluginsReferenceData {
	t.Helper()
	secretData := newVaultAppRoleSecretData(t, roleID, secretID)
	var pluginsSecretData encryptiondata.KMSPluginsReferenceData
	for rawKey, value := range secretData.FlatEntries() {
		require.NoError(t, pluginsSecretData.SetFromRawKey(keyID, rawKey, value))
	}
	return pluginsSecretData
}
