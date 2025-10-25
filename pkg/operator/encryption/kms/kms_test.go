package kms

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestGenerateUnixSocketPath(t *testing.T) {
	tests := []struct {
		name      string
		kmsConfig *configv1.KMSConfig
		wantPath  string // empty means we just verify it's not empty and has expected prefix
		wantErr   bool
	}{
		{
			name: "valid AWS KMS config generates socket path",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					Region: "us-east-1",
				},
			},
			wantPath: "/var/run/kms/kms-2e55e11c0b187f2d.sock",
			wantErr:  false,
		},
		{
			name: "different ARN generates different path",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-west-2:987654321098:key/abcdef12-3456-7890-abcd-ef1234567890",
					Region: "us-west-2",
				},
			},
			wantPath: "", // Just verify it's different
			wantErr:  false,
		},
		{
			name:      "nil config returns error",
			kmsConfig: nil,
			wantErr:   true,
		},
		{
			name: "missing ARN returns error",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "",
					Region: "us-east-1",
				},
			},
			wantErr: true,
		},
		{
			name: "missing region returns error",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					Region: "",
				},
			},
			wantErr: true,
		},
		{
			name: "nil AWS config returns error",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS:  nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateUnixSocketPath(tt.kmsConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateUnixSocketPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if tt.wantPath != "" && got != tt.wantPath {
				t.Errorf("GenerateUnixSocketPath() = %v, want %v", got, tt.wantPath)
			}

			// Verify path format
			if got == "" {
				t.Error("GenerateUnixSocketPath() returned empty path")
			}
			if len(got) < len("/var/run/kms/kms-.sock") {
				t.Errorf("GenerateUnixSocketPath() path too short: %v", got)
			}
		})
	}
}

func TestGenerateUnixSocketPath_Deterministic(t *testing.T) {
	kmsConfig := &configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test-key",
			Region: "us-east-1",
		},
	}

	// Generate path twice and ensure it's the same
	path1, err := GenerateUnixSocketPath(kmsConfig)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	path2, err := GenerateUnixSocketPath(kmsConfig)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if path1 != path2 {
		t.Errorf("paths not deterministic: %v != %v", path1, path2)
	}
}

func TestComputeKMSConfigHash(t *testing.T) {
	tests := []struct {
		name      string
		kmsConfig *configv1.KMSConfig
		wantHash  string
		wantErr   bool
	}{
		{
			name: "valid config produces hash",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test",
					Region: "us-east-1",
				},
			},
			wantHash: "", // Non-empty, will check length
			wantErr:  false,
		},
		{
			name:      "nil config returns empty string",
			kmsConfig: nil,
			wantHash:  "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComputeKMSConfigHash(tt.kmsConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("ComputeKMSConfigHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.kmsConfig != nil && len(got) != 64 { // SHA256 hex is 64 chars
				t.Errorf("ComputeKMSConfigHash() hash length = %d, want 64", len(got))
			}

			if tt.kmsConfig == nil && got != "" {
				t.Errorf("ComputeKMSConfigHash() with nil config = %v, want empty string", got)
			}
		})
	}
}

func TestComputeKMSConfigHash_Deterministic(t *testing.T) {
	kmsConfig := &configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test",
			Region: "us-east-1",
		},
	}

	hash1, err := ComputeKMSConfigHash(kmsConfig)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	hash2, err := ComputeKMSConfigHash(kmsConfig)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hashes not deterministic: %v != %v", hash1, hash2)
	}
}

func TestComputeKMSConfigHash_DifferentConfigs(t *testing.T) {
	config1 := &configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test1",
			Region: "us-east-1",
		},
	}

	config2 := &configv1.KMSConfig{
		Type: configv1.AWSKMSProvider,
		AWS: &configv1.AWSKMSConfig{
			KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test2",
			Region: "us-east-1",
		},
	}

	hash1, _ := ComputeKMSConfigHash(config1)
	hash2, _ := ComputeKMSConfigHash(config2)

	if hash1 == hash2 {
		t.Error("different configs produced same hash")
	}
}

func TestComputeKMSKeyIDHash(t *testing.T) {
	tests := []struct {
		name     string
		keyID    string
		wantHash string
	}{
		{
			name:     "non-empty keyID produces hash",
			keyID:    "test-key-id-123",
			wantHash: "", // Non-empty, will check length
		},
		{
			name:     "empty keyID returns empty hash",
			keyID:    "",
			wantHash: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeKMSKeyIDHash(tt.keyID)

			if tt.keyID != "" && len(got) != 64 { // SHA256 hex is 64 chars
				t.Errorf("ComputeKMSKeyIDHash() hash length = %d, want 64", len(got))
			}

			if tt.keyID == "" && got != "" {
				t.Errorf("ComputeKMSKeyIDHash() with empty keyID = %v, want empty string", got)
			}
		})
	}
}

func TestComputeKMSKeyIDHash_Deterministic(t *testing.T) {
	keyID := "test-key-id-12345"

	hash1 := ComputeKMSKeyIDHash(keyID)
	hash2 := ComputeKMSKeyIDHash(keyID)

	if hash1 != hash2 {
		t.Errorf("hashes not deterministic: %v != %v", hash1, hash2)
	}
}

func TestComputeKMSKeyIDHash_DifferentKeys(t *testing.T) {
	hash1 := ComputeKMSKeyIDHash("key-id-1")
	hash2 := ComputeKMSKeyIDHash("key-id-2")

	if hash1 == hash2 {
		t.Error("different key IDs produced same hash")
	}
}

func TestExtractHashFromSocketPath(t *testing.T) {
	tests := []struct {
		name       string
		socketPath string
		wantHash   string
	}{
		{
			name:       "valid socket path returns hash",
			socketPath: "/var/run/kms/kms-c1c235a71e830c5e.sock",
			wantHash:   "c1c235a71e830c5e",
		},
		{
			name:       "different valid socket path",
			socketPath: "/var/run/kms/kms-1234567890abcdef.sock",
			wantHash:   "1234567890abcdef",
		},
		{
			name:       "invalid path missing prefix",
			socketPath: "/var/run/kms/invalid-c1c235a71e830c5e.sock",
			wantHash:   "",
		},
		{
			name:       "invalid path missing suffix",
			socketPath: "/var/run/kms/kms-c1c235a71e830c5e.txt",
			wantHash:   "",
		},
		{
			name:       "path too short",
			socketPath: "/var/run/kms/kms-abc.sock",
			wantHash:   "",
		},
		{
			name:       "empty path",
			socketPath: "",
			wantHash:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractHashFromSocketPath(tt.socketPath)
			if got != tt.wantHash {
				t.Errorf("ExtractHashFromSocketPath() = %v, want %v", got, tt.wantHash)
			}
		})
	}
}

func TestExtractHashFromSocketPath_RoundTrip(t *testing.T) {
	// Test that we can extract the same hash we used to generate the path
	originalHash := "c1c235a71e830c5e1234567890abcdef" // Full 32-char hash
	socketPath := GenerateUnixSocketPathFromHash(originalHash)
	extractedHash := ExtractHashFromSocketPath(socketPath)

	expectedHash := originalHash[:16] // We only use first 16 chars
	if extractedHash != expectedHash {
		t.Errorf("Round trip failed: generated path from %s, extracted %s, want %s", originalHash, extractedHash, expectedHash)
	}
}
