package pluginlifecycle

import (
	"fmt"
	"path/filepath"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
)

// credentialResolver resolves KMS plugin credentials for a specific keyID
// by looking up secret data and mapping it to values or file paths on disk.
type credentialResolver struct {
	keyID             string
	credentialsDir    string
	pluginsSecretData encryptiondata.KMSPluginsReferenceData
}

// Value returns the credential value for the given secret name and data key.
func (r *credentialResolver) Value(secretName, dataKey string) (string, error) {
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

// FilePath returns the on-disk path where the credential for the given secret name and data key is mounted.
func (r *credentialResolver) FilePath(secretName, dataKey string) (string, error) {
	sd, ok := r.pluginsSecretData.Get(r.keyID)
	if !ok {
		return "", fmt.Errorf("missing secret data for keyID %s", r.keyID)
	}
	rawKey, ok := sd.FlatEntry(secretName, dataKey)
	if !ok {
		return "", fmt.Errorf("missing %s in secret %s for keyID %s", dataKey, secretName, r.keyID)
	}
	secretDataKey := encryptiondata.FormatKMSSecretDataKey(rawKey, r.keyID)
	return filepath.Join(r.credentialsDir, secretDataKey), nil
}
