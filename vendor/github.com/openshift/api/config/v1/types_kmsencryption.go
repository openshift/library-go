package v1

// KMSConfig defines the configuration for the KMS instance
// that will be used with KMS encryption
// +openshift:validation:FeatureGateAwareXValidation:featureGate=KMSEncryption,rule="has(self.type) && self.type == 'Vault' ?  (has(self.vault) && self.vault.vaultAddress != \"\") : !has(self.vault)",message="vault config is required when kms provider type is Vault, and forbidden otherwise"
// +union
type KMSConfig struct {
	// type defines the kind of platform for the KMS provider.
	// Valid values are:
	// - "Vault": HashiCorp Vault KMS (available when KMSEncryption feature gate is enabled)
	//
	// +unionDiscriminator
	// +required
	Type KMSProviderType `json:"type"`

	// vault defines the configuration for the Vault KMS plugin.
	// The plugin connects to a Vault Enterprise server that is managed
	// by the user outside the purview of the control plane.
	// This field must be set when type is Vault, and must be unset otherwise.
	//
	// +openshift:enable:FeatureGate=KMSEncryption
	// +unionMember
	// +optional
	Vault VaultKMSConfig `json:"vault,omitempty,omitzero"`
}

// KMSProviderType is a specific supported KMS provider
// +openshift:validation:FeatureGateAwareEnum:featureGate=KMSEncryption,enum=Vault
type KMSProviderType string

const (
	// VaultKMSProvider represents a supported KMS provider for use with HashiCorp Vault
	VaultKMSProvider KMSProviderType = "Vault"
)

// VaultKMSConfig defines the KMS plugin configuration specific to Vault KMS
type VaultKMSConfig struct {
	// kmsPluginImage specifies the container image for the HashiCorp Vault KMS plugin.
	// The image must be specified using a digest reference (not a tag).
	//
	// Consult the OpenShift documentation for compatible plugin versions with your cluster version,
	// then obtain the image digest for that version from HashiCorp's container registry.
	//
	// For disconnected environments, mirror the plugin image to an accessible registry and
	// reference the mirrored location with its digest.
	//
	// The minimum length is 75 characters (e.g., "r/i@sha256:" + 64 hex characters).
	// The maximum length is 512 characters to accommodate long registry names and repository paths.
	//
	// +kubebuilder:validation:XValidation:rule="self.matches(r'^([a-zA-Z0-9.-]+)(:[0-9]+)?/[a-zA-Z0-9._/-]+@sha256:[a-f0-9]{64}$')",message="kmsPluginImage must be a valid image reference with a SHA256 digest (e.g., 'registry.example.com/vault-plugin@sha256:0123...abcd'). Use '@sha256:<64-character-hex-digest>' instead of image tags like ':latest' or ':v1.0.0'."
	// +kubebuilder:validation:MinLength=75
	// +kubebuilder:validation:MaxLength=512
	// +required
	KMSPluginImage string `json:"kmsPluginImage,omitempty"`

	// vaultAddress specifies the address of the HashiCorp Vault instance.
	// The value must be a valid URL with the https scheme and can be up to 512 characters.
	// Example: https://vault.example.com:8200
	//
	// +kubebuilder:validation:XValidation:rule="isURL(self)",message="vaultAddress must be a valid URL"
	// +kubebuilder:validation:XValidation:rule="url(self).getScheme() == 'https'",message="vaultAddress must use the https scheme"
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:MinLength=1
	// +required
	VaultAddress string `json:"vaultAddress,omitempty"`

	// vaultNamespace specifies the Vault namespace where the Transit secrets engine is mounted.
	// This is only applicable for Vault Enterprise installations.
	// The value can be between 1 and 4096 characters.
	// When this field is not set, no namespace is used.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	// +optional
	VaultNamespace string `json:"vaultNamespace,omitempty"`

	// tls contains the TLS configuration for connecting to the Vault server.
	// When this field is not set, system default TLS settings are used.
	// +optional
	TLS VaultTLSConfig `json:"tls,omitempty,omitzero"`

	// approleSecret references a secret in the openshift-config namespace containing
	// the AppRole credentials used to authenticate with Vault.
	// The secret must contain the following keys:
	//   - "roleID": The AppRole Role ID
	//   - "secretID": The AppRole Secret ID
	//
	// The namespace for the secret referenced by approleSecret is openshift-config.
	//
	// +required
	ApproleSecret *SecretNameReference `json:"approleSecret,omitempty"`

	// transitMount specifies the mount path of the Vault Transit engine.
	// The value can be between 1 and 1024 characters.
	// When this field is not set, it defaults to "transit".
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	// +default="transit"
	// +optional
	TransitMount string `json:"transitMount,omitempty"`

	// transitKey specifies the name of the encryption key in Vault's Transit engine.
	// This key is used to encrypt and decrypt data.
	// The value must be between 1 and 512 characters.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	// +required
	TransitKey string `json:"transitKey,omitempty"`
}

// VaultTLSConfig contains TLS configuration for connecting to Vault.
// +kubebuilder:validation:MinProperties=1
type VaultTLSConfig struct {
	// caBundle references a ConfigMap in the openshift-config namespace containing
	// the CA certificate bundle used to verify the TLS connection to the Vault server.
	// The ConfigMap must contain the CA bundle in the key "ca-bundle.crt".
	// When this field is not set, the system's trusted CA certificates are used.
	//
	// The namespace for the ConfigMap is openshift-config.
	//
	// Example ConfigMap:
	//   apiVersion: v1
	//   kind: ConfigMap
	//   metadata:
	//     name: vault-ca-bundle
	//     namespace: openshift-config
	//   data:
	//     ca-bundle.crt: |
	//       -----BEGIN CERTIFICATE-----
	//       ...
	//       -----END CERTIFICATE-----
	//
	// +optional
	CABundle *ConfigMapNameReference `json:"caBundle,omitempty"`

	// serverName specifies the Server Name Indication (SNI) to use when connecting to Vault via TLS.
	// This is useful when the Vault server's hostname doesn't match its TLS certificate.
	// When this field is not set, the hostname from vaultAddress is used for SNI.
	//
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	// +optional
	ServerName string `json:"serverName,omitempty"`
}
