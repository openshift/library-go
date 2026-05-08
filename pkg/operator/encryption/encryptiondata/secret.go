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
	var kmsCredentials map[string]map[string]string
	for key, value := range encryptionConfigSecret.Data {
		keyID, found, err := kms.KeyIDFromProviderConfigSecretDataKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to extract keyID from data key %s: %w", key, err)
		}
		if found {
			providerConfig, err := encoding.DecodeKMSConfig(value)
			if err != nil {
				return nil, fmt.Errorf("failed to decode KMS provider config for key %s: %w", keyID, err)
			}
			if kmsProviders == nil {
				kmsProviders = map[string]*configv1.KMSConfig{}
			}
			kmsProviders[keyID] = providerConfig
			continue
		}

		credKeyID, credFound, err := kms.KeyIDFromCredentialSecretDataKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to extract keyID from credential data key %s: %w", key, err)
		}
		if credFound {
			credentials := map[string]string{}
			if err := json.Unmarshal(value, &credentials); err != nil {
				return nil, fmt.Errorf("failed to decode KMS credentials for key %s: %w", credKeyID, err)
			}
			if kmsCredentials == nil {
				kmsCredentials = map[string]map[string]string{}
			}
			kmsCredentials[credKeyID] = credentials
		}
	}

	return &Config{Encryption: encryptionConfig, KMSProviders: kmsProviders, KMSCredentials: kmsCredentials}, nil
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
		encodedProvider, err := encoding.EncodeKMSConfig(providerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to encode KMS provider config for key %s: %w", keyID, err)
		}
		dataKey, err := kms.ToProviderConfigSecretDataKeyFor(keyID)
		if err != nil {
			return nil, err
		}
		s.Data[dataKey] = encodedProvider
	}

	for keyID, credentials := range secretData.KMSCredentials {
		credentialsData, err := json.Marshal(credentials)
		if err != nil {
			return nil, fmt.Errorf("failed to encode KMS credentials for key %s: %w", keyID, err)
		}
		dataKey, err := kms.ToCredentialSecretDataKeyFor(keyID)
		if err != nil {
			return nil, err
		}
		s.Data[dataKey] = credentialsData
	}

	return s, nil
}
