package kms

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SchemeGroupVersion identifies the stored configuration; it is not a served API.
var SchemeGroupVersion = schema.GroupVersion{Group: "encryption.operator.openshift.io", Version: "v1"}

func AddToScheme(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion, &KMSPluginConfig{})
	return nil
}

// KMSPluginConfig holds resolved plugin configuration.
// Remove this type when the encryption lifecycle uses unstructured configuration.
type KMSPluginConfig struct {
	metav1.TypeMeta `json:",inline"`
	Type            KMSProviderType      `json:"type"`
	Vault           VaultKMSPluginConfig `json:"vault,omitempty,omitzero"`
}

type KMSProviderType string

const (
	VaultKMSProvider KMSProviderType = "Vault"
)

type VaultSecretReference struct {
	Name string `json:"name,omitempty"`
}

type VaultConfigMapReference struct {
	Name string `json:"name,omitempty"`
}

type VaultAuthentication struct {
	Type    VaultAuthenticationType    `json:"type,omitempty"`
	AppRole VaultAppRoleAuthentication `json:"appRole,omitzero"`
}

type VaultAuthenticationType string

const (
	VaultAuthenticationTypeAppRole VaultAuthenticationType = "AppRole"
)

type VaultAppRoleAuthentication struct {
	Secret VaultSecretReference `json:"secret,omitzero"`
}

type VaultKMSPluginConfig struct {
	KMSPluginImage string `json:"kmsPluginImage,omitempty"`
	VaultAddress   string `json:"vaultAddress,omitempty"`

	VaultNamespace     string `json:"vaultNamespace,omitempty"`
	VaultAuthNamespace string `json:"vaultAuthNamespace,omitempty"`

	TLS            VaultTLSConfig      `json:"tls,omitzero"`
	Authentication VaultAuthentication `json:"authentication,omitzero"`

	VaultKeyPath string `json:"vaultKeyPath,omitempty"`
}

type VaultTLSConfig struct {
	CABundle   VaultConfigMapReference `json:"caBundle,omitzero"`
	ServerName string                  `json:"serverName,omitempty"`
}

func (in *KMSPluginConfig) DeepCopy() *KMSPluginConfig {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func (in *KMSPluginConfig) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	return in.DeepCopy()
}

func (in *VaultKMSPluginConfig) DeepCopy() *VaultKMSPluginConfig {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
