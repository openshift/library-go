package encryptionconfig

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

type EncryptionKeysResourceTuple struct {
	Resource string
	Keys     []apiserverconfigv1.Key
	// an ordered list of an encryption modes thatch matches the keys
	// for example mode[0] matches keys[0]
	Modes []string
}

func CreateEncryptionCfgNoWriteKey(keyID string, keyBase64 string, resources ...string) *Config {
	keysResources := []EncryptionKeysResourceTuple{}
	for _, resource := range resources {
		keysResources = append(keysResources, EncryptionKeysResourceTuple{
			Resource: resource,
			Keys: []apiserverconfigv1.Key{
				{Name: keyID, Secret: keyBase64},
			},
		})

	}
	return CreateEncryptionCfgNoWriteKeyMultipleReadKeys(keysResources)
}

func CreateEncryptionCfgNoWriteKeyMultipleReadKeys(keysResources []EncryptionKeysResourceTuple) *Config {
	ec := &apiserverconfigv1.EncryptionConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EncryptionConfiguration",
			APIVersion: "apiserver.config.k8s.io/v1",
		},
		Resources: []apiserverconfigv1.ResourceConfiguration{},
	}

	for _, keysResource := range keysResources {
		rc := apiserverconfigv1.ResourceConfiguration{
			Resources: []string{keysResource.Resource},
			Providers: []apiserverconfigv1.ProviderConfiguration{
				{
					Identity: &apiserverconfigv1.IdentityConfiguration{},
				},
			},
		}
		for i, key := range keysResource.Keys {
			desiredMode := ""
			if len(keysResource.Modes) == len(keysResource.Keys) {
				desiredMode = keysResource.Modes[i]
			}
			rc.Providers = append(rc.Providers, *createProviderCfg(desiredMode, keysResource.Resource, key))
		}
		ec.Resources = append(ec.Resources, rc)
	}

	return &Config{Encryption: ec}
}

func CreateEncryptionCfgWithWriteKey(keysResources []EncryptionKeysResourceTuple) *Config {
	configurations := []apiserverconfigv1.ResourceConfiguration{}
	for _, keysResource := range keysResources {
		providers := []apiserverconfigv1.ProviderConfiguration{}
		for i, key := range keysResource.Keys {
			desiredMode := ""
			if len(keysResource.Modes) == len(keysResource.Keys) {
				desiredMode = keysResource.Modes[i]
			}
			providers = append(providers, *createProviderCfg(desiredMode, keysResource.Resource, key))
		}
		providers = append(providers, apiserverconfigv1.ProviderConfiguration{
			Identity: &apiserverconfigv1.IdentityConfiguration{},
		})

		configurations = append(configurations, apiserverconfigv1.ResourceConfiguration{
			Resources: []string{keysResource.Resource},
			Providers: providers,
		})
	}

	return &Config{
		Encryption: &apiserverconfigv1.EncryptionConfiguration{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EncryptionConfiguration",
				APIVersion: "apiserver.config.k8s.io/v1",
			},
			Resources: configurations,
		},
	}
}

func createProviderCfg(mode string, resource string, key apiserverconfigv1.Key) *apiserverconfigv1.ProviderConfiguration {
	switch mode {
	case "aesgcm":
		return &apiserverconfigv1.ProviderConfiguration{
			AESGCM: &apiserverconfigv1.AESConfiguration{
				Keys: []apiserverconfigv1.Key{key},
			},
		}
	case "secretbox":
		return &apiserverconfigv1.ProviderConfiguration{
			Secretbox: &apiserverconfigv1.SecretboxConfiguration{
				Keys: []apiserverconfigv1.Key{key},
			},
		}
	case "identity":
		return &apiserverconfigv1.ProviderConfiguration{
			Identity: &apiserverconfigv1.IdentityConfiguration{},
		}
	case "KMS":
		return &apiserverconfigv1.ProviderConfiguration{
			KMS: &apiserverconfigv1.KMSConfiguration{
				APIVersion: "v2",
				Name:       fmt.Sprintf("%s_%s", key.Name, resource),
				Endpoint:   fmt.Sprintf("unix:///var/run/kmsplugin/kms-%s.sock", key.Name),
				Timeout:    &metav1.Duration{Duration: 10 * time.Second},
			},
		}
	default:
		return &apiserverconfigv1.ProviderConfiguration{
			AESCBC: &apiserverconfigv1.AESConfiguration{
				Keys: []apiserverconfigv1.Key{key},
			},
		}
	}
}
