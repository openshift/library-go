package controllers

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

const kmsEndpointFormat = "unix:///var/run/kmsplugin/kms-%d.sock"

// KMSPluginState builds a KMSState by resolving referenced Secrets and ConfigMaps
// from openshift-config. The keyID is used to construct the KMSConfiguration name
// and socket endpoint. The referenced credentials are fetched from the given
// clients and stored as PluginSecretData / PluginConfigMapData.
func KMSPluginState(
	ctx context.Context,
	keyID uint64,
	pluginConfig configv1.KMSPluginConfig,
	secretClient corev1client.SecretsGetter,
	configMapClient corev1client.ConfigMapsGetter,
) (*state.KMSState, error) {
	kmsState := &state.KMSState{
		Encryption: &apiserverv1.KMSConfiguration{
			APIVersion: "v2",
			Name:       fmt.Sprintf("%d", keyID),
			Endpoint:   fmt.Sprintf(kmsEndpointFormat, keyID),
			Timeout:    &metav1.Duration{Duration: defaultKMSTimeout},
		},
		Plugin: pluginConfig,
	}

	providerCfg, err := newKMSProviderConfig(pluginConfig)
	if err != nil {
		return nil, err
	}

	if secretName, expectedKeys, err := providerCfg.referencedSecretName(); err != nil {
		return nil, err
	} else if len(secretName) > 0 {
		refSecret, err := secretClient.Secrets(openshiftConfigNS).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get secret %s in %s: %w", secretName, openshiftConfigNS, err)
		}
		for _, key := range expectedKeys {
			v, ok := refSecret.Data[key]
			if !ok {
				return nil, fmt.Errorf("secret %s in %s is missing required key %q", secretName, openshiftConfigNS, key)
			}
			if err := kmsState.PluginSecretData.Set(secretName, key, v); err != nil {
				return nil, err
			}
		}
	}

	if cmName, expectedKeys, err := providerCfg.referencedConfigMapName(); err != nil {
		return nil, err
	} else if len(cmName) > 0 {
		refCM, err := configMapClient.ConfigMaps(openshiftConfigNS).Get(ctx, cmName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get configmap %s in %s: %w", cmName, openshiftConfigNS, err)
		}
		for _, key := range expectedKeys {
			v, ok := refCM.Data[key]
			if !ok {
				return nil, fmt.Errorf("configmap %s in %s is missing required key %q", cmName, openshiftConfigNS, key)
			}
			if err := kmsState.PluginConfigMapData.Set(cmName, key, []byte(v)); err != nil {
				return nil, err
			}
		}
	}

	return kmsState, nil
}

// kmsProviderConfig abstracts provider-specific KMS logic so that every
// provider-type switch lives in a single factory (newKMSProviderConfig).
type kmsProviderConfig interface {
	sourceConfig() interface{}
	referencedSecretName() (string, []string, error)
	referencedConfigMapName() (string, []string, error)
}

func newKMSProviderConfig(plugin configv1.KMSPluginConfig) (kmsProviderConfig, error) {
	switch plugin.Type {
	case configv1.VaultKMSProvider:
		return &vaultProviderConfig{plugin.Vault}, nil
	default:
		return nil, fmt.Errorf("unsupported KMS provider type %q", plugin.Type)
	}
}

type vaultProviderConfig struct {
	vault configv1.VaultKMSPluginConfig
}

func (v *vaultProviderConfig) sourceConfig() interface{} {
	return v.vault
}

func (v *vaultProviderConfig) referencedSecretName() (string, []string, error) {
	switch v.vault.Authentication.Type {
	case configv1.VaultAuthenticationTypeAppRole:
		return v.vault.Authentication.AppRole.Secret.Name, []string{"role-id", "secret-id"}, nil
	default:
		return "", nil, fmt.Errorf("unsupported Vault authentication type %q", v.vault.Authentication.Type)
	}
}

func (v *vaultProviderConfig) referencedConfigMapName() (string, []string, error) {
	if v.vault.TLS.CABundle.Name == "" {
		return "", nil, nil
	}
	return v.vault.TLS.CABundle.Name, []string{"ca-bundle.crt"}, nil
}
