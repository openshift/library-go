package kms

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

const (
	// unixSocketBaseDir is the base directory for KMS unix sockets
	unixSocketBaseDir = "unix:///var/run/kms"
)

// GenerateUnixSocketPath generates a unique unix socket path from KMS configuration
// by hashing the provider-specific configuration.
// Returns the socket path and the hash value (first 16 characters).
func GenerateUnixSocketPath(kmsConfig *configv1.KMSConfig) (string, string, error) {
	if kmsConfig == nil {
		return "", "", fmt.Errorf("kmsConfig cannot be nil")
	}

	// Determine KMS type and generate path accordingly
	switch kmsConfig.Type {
	case configv1.AWSKMSProvider:
		if kmsConfig.AWS == nil {
			return "", "", fmt.Errorf("AWS KMS config cannot be nil for AWS provider type")
		}
		return generateAWSUnixSocketPath(kmsConfig.AWS)
	default:
		return "", "", fmt.Errorf("unsupported KMS provider type: %s", kmsConfig.Type)
	}
}

// generateAWSUnixSocketPath generates a unique unix socket path from AWS KMS configuration
// by hashing the ARN and region. Returns the socket path and the hash (first 16 characters).
func generateAWSUnixSocketPath(awsConfig *configv1.AWSKMSConfig) (string, string, error) {
	if awsConfig.KeyARN == "" {
		return "", "", fmt.Errorf("AWS KMS KeyARN cannot be empty")
	}

	if awsConfig.Region == "" {
		return "", "", fmt.Errorf("AWS region cannot be empty")
	}

	// Combine KeyARN and region for hashing
	combined := awsConfig.KeyARN + ":" + awsConfig.Region

	// Compute SHA256 hash
	hash := sha256.Sum256([]byte(combined))
	hashStr := hex.EncodeToString(hash[:])

	// Take first 16 characters of hash for shorter path
	shortHash := hashStr[:16]

	socketPath := fmt.Sprintf("%s/kms-%s.sock", unixSocketBaseDir, shortHash)

	return socketPath, shortHash, nil
}

// ComputeKMSKeyHash computes a hash of the KMS key ID returned from the Status endpoint.
// Returns the first 32 characters of the SHA256 hash.
func ComputeKMSKeyHash(configHash, keyID string) []byte {
	if keyID == "" {
		return nil
	}

	combined := configHash + ":" + keyID
	// Compute SHA256 hash
	hash := sha256.Sum256([]byte(combined))
	hashStr := hex.EncodeToString(hash[:])

	return []byte(hashStr[:32])
}

var (
	// endpointHashRegex matches the config hash in endpoint path: unix://var/run/kms/kms-{configHash16}.sock
	endpointHashRegex = regexp.MustCompile(`kms-([a-f0-9]{16})\.sock$`)
	// providerNameRegex matches the key ID hash and key ID in provider name: kms-provider-{keyIDHash32}-{keyID}
	// Example: kms-provider-abcdef1234567890abcdef1234567890-1
	providerNameRegex = regexp.MustCompile(`^kms-provider-([a-f0-9]{32})-(.+)$`)
)

// ExtractKMSHashAndKeyName extracts the KMSConfigHash, KMSKeyIDHash, and key.Name embedded into provider
// name and socket path. Returns (configHash, keyIDHash, keyName, error)
func ExtractKMSHashAndKeyName(provider v1.ProviderConfiguration) (string, string, string, error) {
	// Extract the config hash from the endpoint path: unix://var/run/kms/kms-{configHash}.sock
	endpoint := provider.KMS.Endpoint
	var configHash string
	if matches := endpointHashRegex.FindStringSubmatch(endpoint); len(matches) == 2 {
		configHash = matches[1]
	} else {
		return "", "", "", fmt.Errorf("invalid KMS endpoint format: %s", endpoint)
	}

	// Extract the key ID hash and key ID from the provider name: kms-provider-{keyIDHash16}-{keyID}
	// Example: kms-provider-abcdef1234567890abcdef1234567890-1
	var keyHash, keyName string
	providerName := provider.KMS.Name
	if matches := providerNameRegex.FindStringSubmatch(providerName); len(matches) == 3 {
		keyHash = matches[1]
		keyName = matches[2]
	} else {
		return "", "", "", fmt.Errorf("invalid KMS provider name format: %s", providerName)
	}

	return configHash, base64.StdEncoding.EncodeToString([]byte(keyHash)), keyName, nil
}

// GenerateKMSProviderConfigurationFromKey generates the compatible ProviderConfiguration with
// opinionated and extractable fields. We embed:
// - KMSConfigHash in the socket path (endpoint)
// - KMSKeyIDHash and key.Name in the provider name
// This allows us to extract all three values and detect both config changes and key rotations.
func GenerateKMSProviderConfigurationFromKey(key state.KeyState) v1.ProviderConfiguration {
	// Embed KMSConfigHash in the endpoint so we can extract it
	// This must generate the same format as GenerateUnixSocketPath
	socketPath := fmt.Sprintf("%s/kms-%s.sock", unixSocketBaseDir, key.KMSConfigHash)
	// Embed KMSKeyIDHash and key ID in the provider name so we can extract them when reading back
	// Format: kms-provider-{keyIDHash32}-{keyID}
	// This must match the providerNameRegex
	decoded, _ := base64.StdEncoding.DecodeString(key.Key.Secret)
	providerName := fmt.Sprintf("kms-provider-%s-%s", decoded, key.Key.Name)

	return v1.ProviderConfiguration{
		KMS: &v1.KMSConfiguration{
			APIVersion: "v2",
			Name:       providerName,
			Endpoint:   socketPath,
			Timeout: &metav1.Duration{
				Duration: 10 * time.Second,
			},
		},
	}
}
