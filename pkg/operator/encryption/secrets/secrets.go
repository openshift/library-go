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
	// Today, all possible encryption configs are backed by a secret on the cluster.
	key := state.KeyState{Backed: true}

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
	case state.AESCBC, state.AESGCM, state.SecretBox, state.Identity, state.KMS:
		key.Mode = keyMode
	default:
		return state.KeyState{}, fmt.Errorf("secret %s/%s has invalid mode: %s", s.Namespace, s.Name, keyMode)
	}

	keyData := s.Data[EncryptionSecretKeyDataKey]

	// for non-KMS, non-identity actual key contents cannot not be empty
	if keyMode != state.Identity && keyMode != state.KMS && len(keyData) == 0 {
		return state.KeyState{}, fmt.Errorf("secret %s/%s of mode %q must have non-empty key %q", s.Namespace, s.Name, keyMode, EncryptionSecretKeyDataKey)
	}

	// kms does not populate keys, only uses kms key id and config
	if keyMode == state.KMS {
		kmsKeyID, exists := s.Data[EncryptionSecretKMSKeyId]
		if !exists {
			return state.KeyState{}, fmt.Errorf("secret %s/%s does not contain required data field %q", s.Namespace, s.Name, EncryptionSecretKMSKeyId)
		}
		key.KMSKeyID = string(kmsKeyID)

		kmsConfigJsonData, exists := s.Data[EncryptionSecretKMSConfig]
		if !exists {
			// in the future, we may allow empty KMS config ambiently inferred from the environment
			// depending upon the KMS provider, but today we block it!
			return state.KeyState{}, fmt.Errorf("secret %s/%s does not contain required data field %q", s.Namespace, s.Name, EncryptionSecretKMSConfig)
		}
		err := json.Unmarshal(kmsConfigJsonData, &key.KMSConfig)
		if err != nil {
			return state.KeyState{}, fmt.Errorf("could not load KMS config from secret %s/%s at data field %q: %v", s.Namespace, s.Name, EncryptionSecretKMSConfig, err)
		}
	} else {
		keyID, validKeyID := state.NameToKeyID(s.Name)
		if !validKeyID && keyMode != state.KMS {
			return state.KeyState{}, fmt.Errorf("secret %s/%s has an invalid name", s.Namespace, s.Name)
		}

		key.Key = apiserverconfigv1.Key{
			// we use keyID as the name to limit the length of the field as it is used as a prefix for every value in etcd
			Name:   strconv.FormatUint(keyID, 10),
			Secret: base64.StdEncoding.EncodeToString(keyData),
		}
	}

	return key, nil
}

// FromKeyState converts a key state to a key secret.
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
		Data: make(map[string][]byte),
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

	if ks.Mode == state.KMS {
		// use kms key id instead of key.Name in case of kms
		s.Name = fmt.Sprintf("encryption-key-%s-%s-%s", component, "kms", ks.KMSKeyID)
		s.Data[EncryptionSecretKMSKeyId] = []byte(ks.KMSKeyID)

		kmsConfigJsonData, err := json.Marshal(ks.KMSConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to encode kms config with key id %q: %v", ks.KMSKeyID, err)
		}
		s.Data[EncryptionSecretKMSConfig] = kmsConfigJsonData
	} else {
		s.Data[EncryptionSecretKeyDataKey] = bs
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
