package controllers

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	imagereference "github.com/openshift/library-go/pkg/image/reference"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// ResolveKMSConfig fetches the referenced CR and converts its spec and status image
// into the internal configuration without importing provider API types. Only the
// VaultKMSConfig API is supported until the lifecycle uses a generic interface.
// Unknown spec fields are rejected to avoid silently dropping provider settings.
// Required fields and the image digest are checked before lifecycle use.
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
		Type:     kms.VaultKMSProvider,
	}
	switch obj.GroupVersionKind() {
	case schema.GroupVersionKind{Group: "kms.openshift.io", Version: "v1alpha1", Kind: "VaultKMSConfig"}:
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
		imageRef, err := imagereference.Parse(image)
		if err != nil {
			return kms.KMSPluginConfig{}, fmt.Errorf("invalid KMS plugin configuration status.kmsPluginImage: %w", err)
		}
		if imageRef.ID == "" {
			return kms.KMSPluginConfig{}, fmt.Errorf("KMS plugin configuration status.kmsPluginImage must reference an image by digest")
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
		return kms.KMSPluginConfig{}, fmt.Errorf("unsupported KMS plugin configuration kind %q", obj.GroupVersionKind().String())
	}
	return config, nil
}
