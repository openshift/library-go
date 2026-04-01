package v1

// KMSConfig defines the configuration for the KMS instance
// that will be used with KMSEncryptionProvider encryption
// +kubebuilder:validation:XValidation:rule="has(self.type) && self.type == 'AWS' ?  has(self.aws) : !has(self.aws)",message="aws config is required when kms provider type is AWS, and forbidden otherwise"
// +kubebuilder:validation:XValidation:rule="has(self.type) && self.type == 'Vault' ?  has(self.vault) : !has(self.vault)",message="vault config is required when kms provider type is Vault, and forbidden otherwise"
// +union
type KMSConfig struct {
	// type defines the kind of platform for the KMS provider.
	// Available provider types are AWS and Vault.
	//
	// +unionDiscriminator
	// +required
	Type KMSProviderType `json:"type"`

	// aws defines the key config for using an AWS KMS instance
	// for the encryption. The AWS KMS instance is managed
	// by the user outside the purview of the control plane.
	//
	// +unionMember
	// +optional
	AWS *AWSKMSConfig `json:"aws,omitempty"`

	// vault defines the key config for using a HashiCorp Vault instance
	// for the encryption. The Vault instance is managed
	// by the user outside the purview of the control plane.
	//
	// +unionMember
	// +optional
	Vault *VaultKMSConfig `json:"vault,omitempty"`
}

// AWSKMSConfig defines the KMS config specific to AWS KMS provider
type AWSKMSConfig struct {
	// keyARN specifies the Amazon Resource Name (ARN) of the AWS KMS key used for encryption.
	// The value must adhere to the format `arn:aws:kms:<region>:<account_id>:key/<key_id>`, where:
	// - `<region>` is the AWS region consisting of lowercase letters and hyphens followed by a number.
	// - `<account_id>` is a 12-digit numeric identifier for the AWS account.
	// - `<key_id>` is a unique identifier for the KMS key, consisting of lowercase hexadecimal characters and hyphens.
	//
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="self.matches('^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$')",message="keyARN must follow the format `arn:aws:kms:<region>:<account_id>:key/<key_id>`. The account ID must be a 12 digit number and the region and key ID should consist only of lowercase hexadecimal characters and hyphens (-)."
	// +required
	KeyARN string `json:"keyARN"`
	// region specifies the AWS region where the KMS instance exists, and follows the format
	// `<region-prefix>-<region-name>-<number>`, e.g.: `us-east-1`.
	// Only lowercase letters and hyphens followed by numbers are allowed.
	//
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="self.matches('^[a-z0-9]+(-[a-z0-9]+)*$')",message="region must be a valid AWS region, consisting of lowercase characters, digits and hyphens (-) only."
	// +required
	Region string `json:"region"`
}

// VaultKMSConfig defines the KMS config specific to HashiCorp Vault KMS provider
type VaultKMSConfig struct {
	// image specifies the container image for the Vault KMS plugin sidecar.
	// The value must be a valid container image reference using a sha256 digest,
	// e.g. "quay.io/org/vault-kms-plugin@sha256:abc123...".
	//
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:MinLength=75
	// +required
	Image string `json:"image"`

	// vaultAddress specifies the URL of the Vault server.
	// The value must start with either "http://" or "https://".
	//
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:MinLength=1
	// +required
	VaultAddress string `json:"vaultAddress"`

	// vaultNamespace specifies the Vault namespace where the Transit secrets engine is mounted.
	// This is only applicable for Vault Enterprise installations.
	// The value can be between 1 and 256 characters.
	// When this field is not set, no namespace is used.
	//
	// +optional
	VaultNamespace string `json:"vaultNamespace,omitempty"`

	// tlsCA is a reference to a ConfigMap in the openshift-config namespace containing
	// the CA certificate bundle used to verify the TLS connection to the Vault server.
	// The ConfigMap must contain the CA bundle in the key "ca-bundle.crt".
	// When this field is not set, the system's trusted CA certificates are used.
	//
	// The namespace for the ConfigMap referenced by tlsCA is openshift-config.
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
	TLSCA ConfigMapNameReference `json:"tlsCA,omitempty"`

	// tlsServerName specifies the Server Name Indication (SNI) to use when connecting to Vault via TLS.
	// This is useful when the Vault server's hostname doesn't match its TLS certificate.
	// When this field is not set, no SNI value is sent during the TLS connection.
	//
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	// +optional
	TLSServerName string `json:"tlsServerName,omitempty"`

	// approleSecretRef references a secret in the openshift-config namespace containing
	// the AppRole credentials used to authenticate with Vault.
	// The secret must contain the following keys:
	//   - "roleID": The AppRole Role ID
	//   - "secretID": The AppRole Secret ID
	//
	// +required
	ApproleSecretRef SecretNameReference `json:"approleSecretRef,omitempty"`

	// transitMount specifies the mount path of the Vault Transit engine.
	// The value can be between 1 and 128 characters.
	// When this field is not set, it defaults to "transit".
	//
	// +kubebuilder:default="transit"
	// +optional
	TransitMount string `json:"transitMount,omitempty"`

	// transitKey specifies the name of the encryption key in Vault's Transit engine.
	// This key is used to encrypt and decrypt data.
	// The value must be between 1 and 128 characters.
	//
	// +required
	TransitKey string `json:"transitKey,omitempty"`
}

// KMSProviderType is a specific supported KMS provider
// +kubebuilder:validation:Enum=AWS;Vault
type KMSProviderType string

const (
	// AWSKMSProvider represents a supported KMS provider for use with AWS KMS
	AWSKMSProvider KMSProviderType = "AWS"

	// VaultKMSProvider represents a supported KMS provider for use with HashiCorp Vault
	VaultKMSProvider KMSProviderType = "Vault"
)
