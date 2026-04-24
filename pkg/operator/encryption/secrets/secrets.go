package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

// ToKeyState converts a key secret to a key state.
func ToKeyState(s *corev1.Secret) (state.KeyState, error) {
	data := s.Data[EncryptionSecretKeyDataKey]

	keyID, validKeyID := state.NameToKeyID(s.Name)
	if !validKeyID {
		return state.KeyState{}, fmt.Errorf("secret %s/%s has an invalid name", s.Namespace, s.Name)
	}

	key := state.KeyState{
		Key: apiserverconfigv1.Key{
			// we use keyID as the name to limit the length of the field as it is used as a prefix for every value in etcd
			Name:   strconv.FormatUint(keyID, 10),
			Secret: base64.StdEncoding.EncodeToString(data),
		},
		Backed: true,
	}

	if v, ok := s.Annotations[EncryptionSecretMigratedTimestamp]; ok {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return state.KeyState{}, fmt.Errorf("secret %s/%s has invalid %s annotation: %v", s.Namespace, s.Name, EncryptionSecretMigratedTimestamp, err)
		}
		key.Migrated.Timestamp = ts
	}

	if v, ok := s.Annotations[EncryptionSecretMigratedResources]; ok && len(v) > 0 {
		migrated := &MigratedGroupResources{}
		if err := json.Unmarshal([]byte(v), migrated); err != nil {
			return state.KeyState{}, fmt.Errorf("secret %s/%s has invalid %s annotation: %v", s.Namespace, s.Name, EncryptionSecretMigratedResources, err)
		}
		key.Migrated.Resources = migrated.Resources
	}

	if v, ok := s.Annotations[encryptionSecretInternalReason]; ok && len(v) > 0 {
		key.InternalReason = v
	}
	if v, ok := s.Annotations[encryptionSecretExternalReason]; ok && len(v) > 0 {
		key.ExternalReason = v
	}

	keyMode := state.Mode(s.Annotations[encryptionSecretMode])
	switch keyMode {
	case state.AESCBC, state.AESGCM, state.SecretBox, state.Identity:
		key.Mode = keyMode
	case state.KMS:
		if v, ok := s.Data[EncryptionSecretKMSEncryptionConfig]; ok && len(v) > 0 {
			kmsConfiguration := &apiserverconfigv1.KMSConfiguration{}
			if err := json.Unmarshal(v, kmsConfiguration); err != nil {
				return state.KeyState{}, fmt.Errorf("secret %s/%s has invalid %s data: %w", s.Namespace, s.Name, EncryptionSecretKMSEncryptionConfig, err)
			}
			key.KMSEncryptionConfig = kmsConfiguration
		} else {
			// encryption.apiserver.operator.openshift.io-kms-encryption-config data field is required for KMS
			// encryption mode.
			return state.KeyState{}, fmt.Errorf("%s can not be empty, when mode is KMS", EncryptionSecretKMSEncryptionConfig)
		}
		if v, ok := s.Data[EncryptionSecretKMSProviderConfig]; ok && len(v) > 0 {
			providerConfig := &state.KMSProviderConfig{}
			if err := json.Unmarshal(v, providerConfig); err != nil {
				return state.KeyState{}, fmt.Errorf("secret %s/%s has invalid %s data: %w", s.Namespace, s.Name, EncryptionSecretKMSProviderConfig, err)
			}
			key.KMSProviderConfig = providerConfig
		} else {
			// encryption.apiserver.operator.openshift.io-kms-provider-config data field is required for KMS
			// encryption mode.
			return state.KeyState{}, fmt.Errorf("%s can not be empty, when mode is KMS", EncryptionSecretKMSProviderConfig)
		}
		key.Mode = keyMode
	default:
		return state.KeyState{}, fmt.Errorf("secret %s/%s has invalid mode: %s", s.Namespace, s.Name, keyMode)
	}
	if keyMode != state.Identity && len(data) == 0 {
		return state.KeyState{}, fmt.Errorf("secret %s/%s of mode %q must have non-empty key", s.Namespace, s.Name, keyMode)
	}

	return key, nil
}

// ToKeyState converts a key state to a key secret.
func FromKeyState(component string, ks state.KeyState) (*corev1.Secret, error) {
	bs, err := base64.StdEncoding.DecodeString(ks.Key.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key string")
	}

	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("encryption-key-%s-%s", component, ks.Key.Name),
			Namespace: "openshift-config-managed",
			Labels: map[string]string{
				EncryptionKeySecretsLabel: component,
			},
			Annotations: map[string]string{
				state.KubernetesDescriptionKey: state.KubernetesDescriptionScaryValue,

				encryptionSecretMode:           string(ks.Mode),
				encryptionSecretInternalReason: ks.InternalReason,
				encryptionSecretExternalReason: ks.ExternalReason,
			},
			Finalizers: []string{EncryptionSecretFinalizer},
		},
		Data: map[string][]byte{
			EncryptionSecretKeyDataKey: bs,
		},
		Type: corev1.SecretTypeOpaque,
	}

	if !ks.Migrated.Timestamp.IsZero() {
		s.Annotations[EncryptionSecretMigratedTimestamp] = ks.Migrated.Timestamp.Format(time.RFC3339)
	}
	if len(ks.Migrated.Resources) > 0 {
		migrated := MigratedGroupResources{Resources: ks.Migrated.Resources}
		bs, err := json.Marshal(migrated)
		if err != nil {
			return nil, err
		}
		s.Annotations[EncryptionSecretMigratedResources] = string(bs)
	}

	if ks.KMSEncryptionConfig != nil {
		kmsEncCfgJSON, err := json.Marshal(ks.KMSEncryptionConfig)
		if err != nil {
			return nil, err
		}
		s.Data[EncryptionSecretKMSEncryptionConfig] = kmsEncCfgJSON
	}

	if ks.KMSProviderConfig != nil {
		providerJSON, err := json.Marshal(ks.KMSProviderConfig)
		if err != nil {
			return nil, err
		}
		s.Data[EncryptionSecretKMSProviderConfig] = providerJSON
	}

	return s, nil
}

// HasResource returns whether the given group resource is contained in the migrated group resource list.
func (m *MigratedGroupResources) HasResource(resource schema.GroupResource) bool {
	for _, gr := range m.Resources {
		if gr == resource {
			return true
		}
	}
	return false
}

// ListKeySecrets returns the current key secrets from openshift-config-managed.
func ListKeySecrets(ctx context.Context, secretClient corev1client.SecretsGetter, encryptionSecretSelector metav1.ListOptions) ([]*corev1.Secret, error) {
	encryptionSecretList, err := secretClient.Secrets("openshift-config-managed").List(ctx, encryptionSecretSelector)
	if err != nil {
		return nil, err
	}
	var encryptionSecrets []*corev1.Secret
	for i := range encryptionSecretList.Items {
		encryptionSecrets = append(encryptionSecrets, &encryptionSecretList.Items[i])
	}
	return encryptionSecrets, nil
}
