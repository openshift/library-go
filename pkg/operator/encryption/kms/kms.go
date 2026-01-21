package kms

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

const (
	DefaultEndpoint = "unix:///var/run/kmsplugin/kms.sock"
	DefaultTimeout  = 10 * time.Second
)

// providerNameRegex matches KMS provider names in format: kms-{resource}-{keyID}-{keySecret}
// Example: "kms-secrets-1-XUFAKrxLKna5cZnZEQH8Ug=="
var providerNameRegex = regexp.MustCompile(`^kms-(.+)-(\d+)-([A-Za-z0-9+/=]+)$`)

// KMS represents the configuration for an external Key Management Service provider.
// It contains the endpoint information needed to communicate with the KMS plugin.
// The configuration is serialized to JSON and stored in Kubernetes secrets.
type KMS struct {
	Endpoint string `json:"endpoint"`
}

// NewKMS creates a new KMS configuration with the specified endpoint.
func NewKMS(endpoint string) *KMS {
	return &KMS{
		Endpoint: endpoint,
	}
}

// ToBytes serializes the KMS configuration to JSON.
func (k *KMS) ToBytes() ([]byte, error) {
	jsonBytes, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KMS config: %w", err)
	}
	return jsonBytes, nil
}

// FromBytes deserializes KMS configuration from JSON.
func FromBytes(data []byte) (*KMS, error) {
	kms := &KMS{}
	if err := json.Unmarshal(data, kms); err != nil {
		return nil, fmt.Errorf("failed to unmarshal KMS config: %w", err)
	}
	return kms, nil
}

// ToProviderName converts resource name, key ID, and KMS secret to KMS provider name format: kms-{resourceName}-{keyID}-{keySecret}
// Example: "kms-secrets-1-XUFAKrxLKna5cZnZEQH8Ug=="
func ToProviderName(resourceName string, key apiserverconfigv1.Key) string {
	return fmt.Sprintf("kms-%s-%s-%s", resourceName, key.Name, key.Secret)
}

// FromProviderName extracts the key ID and KMS Secret from a KMS provider name.
// Expected format: kms-{resourceName}-{keyID}-{keySecret}
func FromProviderName(providerName string) (keyID string, kmsKey string, err error) {
	matches := providerNameRegex.FindStringSubmatch(providerName)
	if len(matches) != 4 {
		return "", "", fmt.Errorf("provider name %q has invalid format, expected kms-{resource}-{keyID}-{checksumBase64}", providerName)
	}

	return matches[2], matches[3], nil
}
