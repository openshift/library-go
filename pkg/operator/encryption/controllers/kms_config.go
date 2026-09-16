package controllers

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// ResolveKMSConfig resolves an APIServer KMS reference into the configuration used
// throughout the existing typed encryption lifecycle, without importing provider API types.
// Provider settings come from the referenced CR's spec; the plugin image comes from status.
// Strict conversion rejects unsupported settings instead of silently omitting them.
// Required fields are checked here because external CRD validation cannot be assumed.
func ResolveKMSConfig(ctx context.Context, client dynamic.Interface, reference configv1.KMSPluginConfig) (kms.KMSPluginConfig, error) {
	if client == nil {
		return kms.KMSPluginConfig{}, fmt.Errorf("dynamic client is required to resolve KMS plugin configuration")
	}
	ref := reference.PluginConfig
	gv, err := schema.ParseGroupVersion(ref.APIVersion)
	if err != nil {
		return kms.KMSPluginConfig{}, fmt.Errorf("invalid KMS plugin configuration apiVersion %q: %w", ref.APIVersion, err)
	}
	obj, err := client.Resource(gv.WithResource(ref.Resource)).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return kms.KMSPluginConfig{}, fmt.Errorf("failed to get KMS plugin configuration %s %s/%s: %w", ref.APIVersion, ref.Resource, ref.Name, err)
	}
	if obj == nil || len(obj.Object) == 0 {
		return kms.KMSPluginConfig{}, fmt.Errorf("KMS plugin configuration must not be nil or empty")
	}
	config := kms.KMSPluginConfig{
		TypeMeta: metav1.TypeMeta{APIVersion: kms.SchemeGroupVersion.String(), Kind: "KMSPluginConfig"},
		Type:     kms.KMSProviderType(reference.Type),
	}
	switch reference.Type {
	case configv1.VaultKMSProvider:
		spec, _, err := unstructured.NestedMap(obj.Object, "spec")
		if err != nil {
			return kms.KMSPluginConfig{}, fmt.Errorf("failed to read KMS plugin configuration spec: %w", err)
		}
		if spec != nil {
			// Reject unknown fields so provider settings are not silently dropped from the internal configuration.
			if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(spec, &config.Vault, true); err != nil {
				return kms.KMSPluginConfig{}, fmt.Errorf("failed to convert Vault KMS plugin configuration spec: %w", err)
			}
		}
		image, _, err := unstructured.NestedString(obj.Object, "status", "kmsPluginImage")
		if err != nil {
			return kms.KMSPluginConfig{}, fmt.Errorf("failed to read KMS plugin image: %w", err)
		}
		config.Vault.KMSPluginImage = image
		if config.Vault.KMSPluginImage == "" {
			return kms.KMSPluginConfig{}, fmt.Errorf("KMS plugin configuration status.kmsPluginImage must not be empty")
		}
		if config.Vault.VaultAddress == "" {
			return kms.KMSPluginConfig{}, fmt.Errorf("KMS plugin configuration spec.vaultAddress must not be empty")
		}
		if config.Vault.VaultKeyPath == "" {
			return kms.KMSPluginConfig{}, fmt.Errorf("KMS plugin configuration spec.vaultKeyPath must not be empty")
		}
		if config.Vault.Authentication.Type == "" {
			return kms.KMSPluginConfig{}, fmt.Errorf("KMS plugin configuration spec.authentication.type must not be empty")
		}
		if config.Vault.Authentication.Type == kms.VaultAuthenticationTypeAppRole && config.Vault.Authentication.AppRole.Secret.Name == "" {
			return kms.KMSPluginConfig{}, fmt.Errorf("KMS plugin configuration spec.authentication.appRole.secret.name must not be empty")
		}
	default:
		return kms.KMSPluginConfig{}, fmt.Errorf("unsupported KMS provider type %q", reference.Type)
	}
	return config, nil
}
