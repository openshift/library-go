package kms

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestGenerateUnixSocketPath(t *testing.T) {
	tests := []struct {
		name      string
		kmsConfig *configv1.KMSConfig
		wantPath  string
		wantHash  string
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
			wantPath: "unix://var/run/kms/kms-2e55e11c0b187f2d.sock",
			wantHash: "2e55e11c0b187f2d",
			wantErr:  false,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotHash, err := GenerateUnixSocketPath(tt.kmsConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateUnixSocketPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if gotPath != tt.wantPath {
				t.Fatalf("GenerateUnixSocketPath() gotPath = %v, want %v", gotPath, tt.wantPath)
			}
			if gotHash != tt.wantHash {
				t.Fatalf("GenerateUnixSocketPath() gotHash = %v, want %v", gotHash, tt.wantHash)
			}
		})
	}

	// Test determinism - same config should always generate same path
	t.Run("deterministic generation", func(t *testing.T) {
		kmsConfig := &configv1.KMSConfig{
			Type: configv1.AWSKMSProvider,
			AWS: &configv1.AWSKMSConfig{
				KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test-key",
				Region: "us-east-1",
			},
		}

		path1, hash1, err := GenerateUnixSocketPath(kmsConfig)
		if err != nil {
			t.Fatalf("first call failed: %v", err)
		}

		path2, hash2, err := GenerateUnixSocketPath(kmsConfig)
		if err != nil {
			t.Fatalf("second call failed: %v", err)
		}

		if path1 != path2 {
			t.Errorf("paths not deterministic: %v != %v", path1, path2)
		}

		if hash1 != hash2 {
			t.Errorf("hashes not deterministic: %v != %v", hash1, hash2)
		}
	})
}
