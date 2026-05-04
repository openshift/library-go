package encryptiondata

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

// EncryptionConfSecretName is the name of the final encryption config secret that is revisioned per apiserver rollout.
const EncryptionConfSecretName = "encryption-config"

// EncryptionConfSecretKey is the map data key used to store the raw bytes of the final encryption config.
const EncryptionConfSecretKey = "encryption-config"

func FromSecret(encryptionConfigSecret *corev1.Secret) (*Config, error) {
	data, ok := encryptionConfigSecret.Data[EncryptionConfSecretKey]
	if !ok {
		return nil, nil
	}
	encryptionConfig, err := encoding.DecodeEncryptionConfiguration(data)
	if err != nil {
		return nil, err
	}
	var kmsProviders map[string]*configv1.KMSConfig
	for key, value := range encryptionConfigSecret.Data {
		keyID, ok := kms.ProviderConfigKeyID(key)
		if !ok {
			continue
		}
		providerConfig := &configv1.KMSConfig{}
		if err := json.Unmarshal(value, providerConfig); err != nil {
			return nil, fmt.Errorf("failed to decode KMS provider config for key %s: %w", keyID, err)
		}
		if kmsProviders == nil {
			kmsProviders = map[string]*configv1.KMSConfig{}
		}
		kmsProviders[keyID] = providerConfig
	}

	return &Config{Encryption: encryptionConfig, KMSProviders: kmsProviders}, nil
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

	for keyID, providerConfig := range secretData.KMSProviders {
		providerJSON, err := json.Marshal(providerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to encode KMS provider config for key %s: %v", keyID, err)
		}
		s.Data[kms.ProviderConfigDataKey(keyID)] = providerJSON
	}

	return s, nil
}
