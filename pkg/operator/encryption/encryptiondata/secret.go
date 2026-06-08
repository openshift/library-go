package encryptiondata

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

const pluginConfigDataKeyPrefix = "kms-plugin-config-"

// toPluginConfigSecretDataKeyFor constructs the data key for storing a KMS plugin config in the encryption-config Secret.
// The keyID must be a valid non-negative integer string.
func toPluginConfigSecretDataKeyFor(keyID string) (string, error) {
	if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
		return "", fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
	}
	return pluginConfigDataKeyPrefix + keyID, nil
}

// keyIDFromPluginConfigSecretDataKey extracts the keyID from a kms-plugin-config data key.
// Returns the keyID and true if the key matches the "kms-plugin-config-<keyID>" pattern.
func keyIDFromPluginConfigSecretDataKey(dataKey string) (string, bool, error) {
	keyID, found := strings.CutPrefix(dataKey, pluginConfigDataKeyPrefix)
	if !found || len(keyID) == 0 {
		return "", false, nil
	}
	if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
		return "", false, fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
	}
	return keyID, true, nil
}

const (
	// EncryptionConfSecretName is the name of the final encryption config secret that is revisioned per apiserver rollout.
	EncryptionConfSecretName = "encryption-config"
	// EncryptionConfSecretKey is the map data key used to store the raw bytes of the final encryption config.
	EncryptionConfSecretKey = "encryption-config"
	// encryptionConfigSecretDataPrefix is the data key prefix for KMS plugin secret
	// data entries in the encryption-config Secret. Full key: "kms-plugin-secret-{secretName}_{dataKey}-{keyID}".
	encryptionConfigSecretDataPrefix = "kms-plugin-secret-"
	// encryptionConfigConfigMapDataPrefix is the data key prefix for KMS plugin configmap
	// data entries in the encryption-config Secret. Full key: "kms-plugin-configmap-{cmName}_{dataKey}-{keyID}".
	encryptionConfigConfigMapDataPrefix = "kms-plugin-configmap-"
)

func FromSecret(encryptionConfigSecret *corev1.Secret) (*Config, error) {
	data, ok := encryptionConfigSecret.Data[EncryptionConfSecretKey]
	if !ok {
		return nil, nil
	}
	encryptionConfig, err := encoding.DecodeEncryptionConfiguration(data)
	if err != nil {
		return nil, err
	}
	var kmsPlugins map[string]configv1.KMSPluginConfig
	for key, value := range encryptionConfigSecret.Data {
		// Not all data keys are plugin configs — the Secret also contains the
		// encryption-config entry, so skip keys that don't match the pattern.
		keyID, found, err := keyIDFromPluginConfigSecretDataKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to extract keyID from data key %s: %w", key, err)
		}
		if !found {
			continue
		}
		pluginConfig, err := encoding.DecodeKMSPluginConfig(value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode KMS plugin config for key %s: %w", keyID, err)
		}
		if kmsPlugins == nil {
			kmsPlugins = map[string]configv1.KMSPluginConfig{}
		}
		if _, exists := kmsPlugins[keyID]; exists {
			return nil, fmt.Errorf("duplicate KMS plugin config for keyID %s", keyID)
		}
		kmsPlugins[keyID] = pluginConfig
	}

	// Extract secret data entries from the encryption-config Secret.
	// Data keys follow the format "kms-plugin-secret-{secretName}_{dataKey}-{keyID}"
	// (e.g. "kms-plugin-secret-app-role_role-id-1"). keyIDFromSecretDataKey
	// returns the keyID (e.g. "1") and the combined key (e.g. "app-role_role-id"),
	// which is then split on "_" to recover secretName and dataKey.
	var kmsPluginsSecretData KMSPluginsReferenceData
	for key, value := range encryptionConfigSecret.Data {
		keyID, rawKey, found, err := parseKMSReferenceDataKey(key, encryptionConfigSecretDataPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to parse secret data key %s: %w", key, err)
		}
		if !found {
			continue
		}
		if err := kmsPluginsSecretData.SetFromRawKey(keyID, rawKey, value); err != nil {
			return nil, fmt.Errorf("failed to set key %s: %w", key, err)
		}
	}

	// Extract configmap data entries from the encryption-config Secret.
	// Data keys follow the format "kms-plugin-configmap-{cmName}_{dataKey}-{keyID}".
	var kmsPluginsConfigMapData KMSPluginsReferenceData
	for key, value := range encryptionConfigSecret.Data {
		keyID, rawKey, found, err := parseKMSReferenceDataKey(key, encryptionConfigConfigMapDataPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to parse configmap data key %s: %w", key, err)
		}
		if !found {
			continue
		}
		if err := kmsPluginsConfigMapData.SetFromRawKey(keyID, rawKey, value); err != nil {
			return nil, fmt.Errorf("failed to set key %s: %w", key, err)
		}
	}

	return &Config{Encryption: encryptionConfig, KMSPlugins: kmsPlugins, KMSPluginsSecretData: kmsPluginsSecretData, KMSPluginsConfigMapData: kmsPluginsConfigMapData}, nil
}

func ToSecret(ns, name string, secretData *Config) (*corev1.Secret, error) {
	if !secretData.HasEncryptionConfiguration() {
		return nil, fmt.Errorf("secret %s/%s has no encryption config", ns, name)
	}

	rawEncryptionCfg, err := encoding.EncodeEncryptionConfiguration(secretData.Encryption)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the encryption config: %v", err)
	}

	s := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Annotations: map[string]string{
				state.KubernetesDescriptionKey: state.KubernetesDescriptionScaryValue,
			},
			Finalizers: []string{"encryption.apiserver.operator.openshift.io/deletion-protection"},
		},
		Data: map[string][]byte{
			EncryptionConfSecretName: rawEncryptionCfg,
		},
		Type: corev1.SecretTypeOpaque,
	}

	for keyID, pluginConfig := range secretData.KMSPlugins {
		encodedPlugin, err := encoding.EncodeKMSPluginConfig(pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to encode KMS plugin config for key %s: %w", keyID, err)
		}
		dataKey, err := toPluginConfigSecretDataKeyFor(keyID)
		if err != nil {
			return nil, err
		}
		s.Data[dataKey] = encodedPlugin
	}

	// Write secret data entries to the encryption-config Secret.
	// Each entry from FlatEntries() (e.g. "app-role_role-id") is combined with the keyID
	// (e.g. "1") to produce "kms-plugin-secret-app-role_role-id-1".
	for keyID, flatEntries := range secretData.KMSPluginsSecretData.FlatEntriesByKeyID() {
		for rawKey, value := range flatEntries {
			s.Data[FormatKMSSecretDataKey(rawKey, keyID)] = value
		}
	}

	for keyID, flatEntries := range secretData.KMSPluginsConfigMapData.FlatEntriesByKeyID() {
		for rawKey, value := range flatEntries {
			s.Data[formatKMSConfigMapDataKey(rawKey, keyID)] = value
		}
	}

	return s, nil
}

// ExtractUniqueAndSortedKMSConfigurations collects deduplicated KMS providers from the
// EncryptionConfiguration, strips the resource suffix from each Name, and returns them
// sorted by keyID descending. Duplicate keyIDs with mismatched config (ignoring Name) error out.
func ExtractUniqueAndSortedKMSConfigurations(secretData *Config) ([]*apiserverconfigv1.KMSConfiguration, error) {
	if !secretData.HasEncryptionConfiguration() {
		return nil, fmt.Errorf("encryption configuration is required")
	}
	byKeyID := map[string]*apiserverconfigv1.KMSConfiguration{}
	for _, resource := range secretData.Encryption.Resources {
		for _, provider := range resource.Providers {
			if provider.KMS == nil {
				continue
			}
			keyID, err := getKeyIDFromPluginName(provider.KMS.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to parse key ID from plugin name %q: %w", provider.KMS.Name, err)
			}
			if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
				return nil, fmt.Errorf("key ID %q is not a valid integer: %w", keyID, err)
			}
			kmsCopy := provider.KMS.DeepCopy()
			kmsCopy.Name = keyID
			if existing, exists := byKeyID[keyID]; exists {
				if !equality.Semantic.DeepEqual(existing, kmsCopy) {
					return nil, fmt.Errorf("KMS configuration mismatch for keyID %s: configs from different resources must be identical", keyID)
				}
			}
			byKeyID[keyID] = kmsCopy
		}
	}

	result := make([]*apiserverconfigv1.KMSConfiguration, 0, len(byKeyID))
	for _, v := range byKeyID {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool {
		iKeyID, _ := strconv.ParseUint(result[i].Name, 10, 64)
		jKeyID, _ := strconv.ParseUint(result[j].Name, 10, 64)
		return iKeyID > jKeyID
	})
	return result, nil
}

// FormatKMSSecretDataKey returns the data key used in the encryption-config Secret
// for a KMS plugin secret entry: "kms-plugin-secret-{rawKey}-{keyID}",
// where rawKey is the combined "secretName_dataKey" from KMSSecretData.FlatEntry.
//
// Note:
//
// It does not validate inputs. The callers are expected to use KMSSecretData.Set,
// which rejects empty values and underscores in secretName.
func FormatKMSSecretDataKey(rawKey, keyID string) string {
	return fmt.Sprintf("%s%s-%s", encryptionConfigSecretDataPrefix, rawKey, keyID)
}

// formatKMSConfigMapDataKey returns the data key used in the encryption-config Secret
// for a KMS plugin configmap entry: "kms-plugin-configmap-{rawKey}-{keyID}",
// where rawKey is the combined "configMapName_dataKey" from KMSReferenceData.FlatEntry.
//
// Note:
//
// It does not validate inputs. The callers are expected to use KMSReferenceData.Set,
// which rejects empty values and underscores in referenceName.
func formatKMSConfigMapDataKey(rawKey, keyID string) string {
	return fmt.Sprintf("%s%s-%s", encryptionConfigConfigMapDataPrefix, rawKey, keyID)
}

func parseKMSReferenceDataKey(dataKey, prefix string) (keyID, rawKey string, found bool, err error) {
	rest, found := strings.CutPrefix(dataKey, prefix)
	if !found {
		return "", "", false, nil
	}
	i := strings.LastIndex(rest, "-")
	if i < 1 {
		return "", "", false, nil
	}
	keyID = rest[i+1:]
	if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
		return "", "", false, fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
	}
	return keyID, rest[:i], true, nil
}
