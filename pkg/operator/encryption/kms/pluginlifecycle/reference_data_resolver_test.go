package pluginlifecycle

import (
	"path/filepath"
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/stretchr/testify/require"
)

func TestReferenceDataResolver_SecretValue(t *testing.T) {
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
			r := &referenceDataResolver{
				keyID:             tc.keyID,
				pluginsSecretData: pluginsSecretData,
			}

			got, err := r.SecretValue(tc.secretName, tc.dataKey)
			if tc.expectErr != "" {
				require.EqualError(t, err, tc.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestReferenceDataResolver_SecretFilePath(t *testing.T) {
	const keyID = "42"
	const referenceDataDir = "/etc/kubernetes/static-pod-resources/secrets/encryption-config"

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
			expected:   filepath.Join(referenceDataDir, encryptiondata.FormatKMSSecretDataKey("vault-approle_secret-id", keyID)),
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
			r := &referenceDataResolver{
				keyID:             tc.keyID,
				referenceDataDir:  referenceDataDir,
				pluginsSecretData: pluginsSecretData,
			}

			got, err := r.SecretFilePath(tc.secretName, tc.dataKey)
			if tc.expectErr != "" {
				require.EqualError(t, err, tc.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestReferenceDataResolver_ConfigMapFilePath(t *testing.T) {
	const keyID = "42"
	const referenceDataDir = "/etc/kubernetes/static-pod-resources/secrets/encryption-config"

	pluginsConfigMapData := newTestPluginsConfigMapData(t, keyID, "my-ca-bundle")

	tests := []struct {
		name          string
		keyID         string
		configMapName string
		dataKey       string
		expected      string
		expectErr     string
	}{
		{
			name:          "returns correct path",
			keyID:         keyID,
			configMapName: "vault-ca-bundle",
			dataKey:       "ca-bundle.crt",
			expected:      filepath.Join(referenceDataDir, encryptiondata.FormatKMSConfigMapDataKey("vault-ca-bundle_ca-bundle.crt", keyID)),
		},
		{
			name:          "missing keyID",
			keyID:         "unknown",
			configMapName: "vault-ca-bundle",
			dataKey:       "ca-bundle.crt",
			expectErr:     "missing configMap data for keyID unknown",
		},
		{
			name:          "missing data key",
			keyID:         keyID,
			configMapName: "vault-ca-bundle",
			dataKey:       "nonexistent",
			expectErr:     "missing nonexistent in configMap vault-ca-bundle for keyID 42",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &referenceDataResolver{
				keyID:                tc.keyID,
				referenceDataDir:     referenceDataDir,
				pluginsConfigMapData: pluginsConfigMapData,
			}

			got, err := r.ConfigMapFilePath(tc.configMapName, tc.dataKey)
			if tc.expectErr != "" {
				require.EqualError(t, err, tc.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func newTestPluginsConfigMapData(t *testing.T, keyID, caBundle string) encryptiondata.KMSPluginsReferenceData {
	t.Helper()
	var rd state.KMSReferenceData
	require.NoError(t, rd.Set("vault-ca-bundle", "ca-bundle.crt", []byte(caBundle)))
	var pluginsConfigMapData encryptiondata.KMSPluginsReferenceData
	for rawKey, value := range rd.FlatEntries() {
		require.NoError(t, pluginsConfigMapData.SetFromRawKey(keyID, rawKey, value))
	}
	return pluginsConfigMapData
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
