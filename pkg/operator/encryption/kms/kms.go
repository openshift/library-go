package kms

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
)

const (
	// unixSocketBaseDir is the base directory for KMS unix sockets
	unixSocketBaseDir = "/var/run/kms"
)

// GenerateUnixSocketPath generates a unique unix socket path from KMS configuration
// by hashing the provider-specific configuration
func GenerateUnixSocketPath(kmsConfig *configv1.KMSConfig) (string, error) {
	if kmsConfig == nil {
		return "", fmt.Errorf("kmsConfig cannot be nil")
	}

	// Determine KMS type and generate path accordingly
	switch kmsConfig.Type {
	case configv1.AWSKMSProvider:
		if kmsConfig.AWS == nil {
			return "", fmt.Errorf("AWS KMS config cannot be nil for AWS provider type")
		}
		return generateAWSUnixSocketPath(kmsConfig.AWS)
	default:
		return "", fmt.Errorf("unsupported KMS provider type: %s", kmsConfig.Type)
	}
}

// generateAWSUnixSocketPath generates a unique unix socket path from AWS KMS configuration
// by hashing the ARN and region
func generateAWSUnixSocketPath(awsConfig *configv1.AWSKMSConfig) (string, error) {
	if awsConfig.KeyARN == "" {
		return "", fmt.Errorf("AWS KMS KeyARN cannot be empty")
	}

	if awsConfig.Region == "" {
		return "", fmt.Errorf("AWS region cannot be empty")
	}

	// Combine KeyARN and region for hashing
	combined := awsConfig.KeyARN + ":" + awsConfig.Region

	// Compute SHA256 hash
	hash := sha256.Sum256([]byte(combined))
	hashStr := hex.EncodeToString(hash[:])

	// Take first 16 characters of hash for shorter path
	shortHash := hashStr[:16]

	// Generate unix socket path
	socketPath := filepath.Join(unixSocketBaseDir, fmt.Sprintf("kms-%s.sock", shortHash))

	return socketPath, nil
}

// GenerateUnixSocketPathFromHash generates a unix socket path from a KMS config hash
// This is used when we have the hash but not the original config
func GenerateUnixSocketPathFromHash(configHash string) string {
	if len(configHash) < 16 {
		return ""
	}

	shortHash := configHash[:16]

	return filepath.Join(unixSocketBaseDir, fmt.Sprintf("kms-%s.sock", shortHash))
}

// ExtractHashFromSocketPath extracts the KMS config hash from a unix socket path
// Returns the short hash (16 characters) embedded in the socket path
func ExtractHashFromSocketPath(socketPath string) string {
	// Expected format: /var/run/kms/kms-{16-char-hash}.sock
	base := filepath.Base(socketPath)

	// Remove "kms-" prefix and ".sock" suffix
	if len(base) < 20 { // "kms-" (4) + hash (16) = 20 minimum
		return ""
	}

	if !strings.HasPrefix(base, "kms-") || !strings.HasSuffix(base, ".sock") {
		return ""
	}

	// Extract hash between "kms-" and ".sock"
	hash := base[4 : len(base)-5]

	return hash
}

// ComputeKMSConfigHash computes a SHA256 hash of the KMS configuration
// This can be used to detect changes in the KMS configuration
func ComputeKMSConfigHash(kmsConfig *configv1.KMSConfig) (string, error) {
	if kmsConfig == nil {
		return "", nil
	}

	// Marshal the configuration to JSON for consistent hashing
	configJSON, err := json.Marshal(kmsConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal KMS config: %w", err)
	}

	// Compute SHA256 hash
	hash := sha256.Sum256(configJSON)
	return hex.EncodeToString(hash[:]), nil
}

// ComputeKMSKeyIDHash computes a SHA256 hash of the KMS key ID
// This can be used to detect changes in the KMS key ID
func ComputeKMSKeyIDHash(keyID string) string {
	if keyID == "" {
		return ""
	}

	// Compute SHA256 hash
	hash := sha256.Sum256([]byte(keyID))
	return hex.EncodeToString(hash[:])
}
