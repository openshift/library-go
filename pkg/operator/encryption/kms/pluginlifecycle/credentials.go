package pluginlifecycle

import (
	"fmt"
	"path/filepath"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
)

// referenceDataResolver resolves KMS plugin reference data for a specific keyID
// by looking up secret and configMap data and mapping it to values or file paths on disk.
type referenceDataResolver struct {
	keyID                string
	referenceDataDir     string
	pluginsSecretData    encryptiondata.KMSPluginsReferenceData
	pluginsConfigMapData encryptiondata.KMSPluginsReferenceData
}

// SecretValue returns the value for the given secret name and data key.
func (r *referenceDataResolver) SecretValue(secretName, dataKey string) (string, error) {
	sd, ok := r.pluginsSecretData.Get(r.keyID)
	if !ok {
		return "", fmt.Errorf("missing secret data for keyID %s", r.keyID)
	}
	v, ok := sd.Get(secretName, dataKey)
	if !ok {
		return "", fmt.Errorf("missing %s in secret %s for keyID %s", dataKey, secretName, r.keyID)
	}
	return string(v), nil
}

// SecretFilePath returns the on-disk path where the data for the given secret name and data key is mounted.
func (r *referenceDataResolver) SecretFilePath(secretName, dataKey string) (string, error) {
	sd, ok := r.pluginsSecretData.Get(r.keyID)
	if !ok {
		return "", fmt.Errorf("missing secret data for keyID %s", r.keyID)
	}
	rawKey, ok := sd.FlatEntry(secretName, dataKey)
	if !ok {
		return "", fmt.Errorf("missing %s in secret %s for keyID %s", dataKey, secretName, r.keyID)
	}
	secretDataKey := encryptiondata.FormatKMSSecretDataKey(rawKey, r.keyID)
	return filepath.Join(r.referenceDataDir, secretDataKey), nil
}

// ConfigMapFilePath returns the on-disk path where the data for the given configMap name and data key is mounted.
func (r *referenceDataResolver) ConfigMapFilePath(configMapName, dataKey string) (string, error) {
	cd, ok := r.pluginsConfigMapData.Get(r.keyID)
	if !ok {
		return "", fmt.Errorf("missing configMap data for keyID %s", r.keyID)
	}
	rawKey, ok := cd.FlatEntry(configMapName, dataKey)
	if !ok {
		return "", fmt.Errorf("missing %s in configMap %s for keyID %s", dataKey, configMapName, r.keyID)
	}
	configMapDataKey := encryptiondata.FormatKMSConfigMapDataKey(rawKey, r.keyID)
	return filepath.Join(r.referenceDataDir, configMapDataKey), nil
}
