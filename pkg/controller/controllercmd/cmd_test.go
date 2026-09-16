package controllercmd

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
)

func TestAddDefaultRotationToConfig_SelfSignedCertLifetime(t *testing.T) {
	// Skip if service-serving-cert files exist, as we need to test the self-signed cert path
	if hasServiceServingCerts("/var/run/secrets/serving-cert") {
		t.Skip("skipping: service-serving-cert exists, cannot test self-signed cert generation")
	}

	c := &ControllerCommandConfig{
		componentName: "test-controller",
		basicFlags:    &ControllerFlags{},
	}

	config := &operatorv1alpha1.GenericOperatorConfig{
		ServingInfo: configv1.HTTPServingInfo{},
	}
	config.ServingInfo.CertFile = ""
	config.ServingInfo.KeyFile = ""

	_, _, err := c.AddDefaultRotationToConfig(config, []byte{})
	if err != nil {
		t.Fatalf("AddDefaultRotationToConfig failed: %v", err)
	}

	if config.ServingInfo.CertFile == "" {
		t.Fatal("expected CertFile to be set, got empty string")
	}
	if config.ServingInfo.KeyFile == "" {
		t.Fatal("expected KeyFile to be set, got empty string")
	}

	certPEM, err := os.ReadFile(config.ServingInfo.CertFile)
	if err != nil {
		t.Fatalf("failed to read generated certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	actualLifetime := cert.NotAfter.Sub(cert.NotBefore)
	expectedLifetime := 30 * 24 * time.Hour

	// Allow 1 minute tolerance
	tolerance := 1 * time.Minute
	lowerBound := expectedLifetime - tolerance
	upperBound := expectedLifetime + tolerance

	if actualLifetime < lowerBound || actualLifetime > upperBound {
		t.Errorf("certificate lifetime is incorrect: expected %v (30 days), got %v", expectedLifetime, actualLifetime)
	}

	// Ensure the certificate is not already expired (would indicate nanosecond lifetime bug)
	if time.Now().After(cert.NotAfter) {
		t.Errorf("certificate is already expired - likely created with nanosecond lifetime (the bug)")
	}

	// Verify the certificate won't expire in the next 29 days
	minValidUntil := time.Now().Add(29 * 24 * time.Hour)
	if cert.NotAfter.Before(minValidUntil) {
		t.Errorf("certificate expires too soon: expected valid for ~30 days, expires %v", cert.NotAfter)
	}
}

func TestHasServiceServingCerts(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(string) error
		expected bool
	}{
		{
			name: "both cert and key exist",
			setup: func(dir string) error {
				if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("cert"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(dir, "tls.key"), []byte("key"), 0644)
			},
			expected: true,
		},
		{
			name: "only cert exists",
			setup: func(dir string) error {
				return os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("cert"), 0644)
			},
			expected: false,
		},
		{
			name: "only key exists",
			setup: func(dir string) error {
				return os.WriteFile(filepath.Join(dir, "tls.key"), []byte("key"), 0644)
			},
			expected: false,
		},
		{
			name:     "neither exists",
			setup:    func(dir string) error { return nil },
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			if err := tt.setup(tmpDir); err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			result := hasServiceServingCerts(tmpDir)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAddDefaultRotationToConfig(t *testing.T) {
	tests := []struct {
		name              string
		configFile        string
		existingCertFile  string
		existingKeyFile   string
		expectGenerated   bool
		expectObservedLen int
	}{
		{
			name:              "generates self-signed cert when none specified",
			expectGenerated:   true,
			expectObservedLen: 2, // service cert paths
		},
		{
			name:              "does not generate when certs already specified",
			existingCertFile:  "/existing/tls.crt",
			existingKeyFile:   "/existing/tls.key",
			expectGenerated:   false,
			expectObservedLen: 2,
		},
		{
			name:              "observes config file when provided",
			configFile:        "test-config.yaml",
			expectGenerated:   true,
			expectObservedLen: 3, // service cert paths + config file
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			var configFile string
			if tt.configFile != "" {
				configFile = filepath.Join(tmpDir, tt.configFile)
				if err := os.WriteFile(configFile, []byte("test-content"), 0644); err != nil {
					t.Fatalf("failed to create config file: %v", err)
				}
			}

			c := &ControllerCommandConfig{
				componentName: "test-controller",
				basicFlags: &ControllerFlags{
					ConfigFile: configFile,
				},
			}

			config := &operatorv1alpha1.GenericOperatorConfig{
				ServingInfo: configv1.HTTPServingInfo{},
			}
			config.ServingInfo.CertFile = tt.existingCertFile
			config.ServingInfo.KeyFile = tt.existingKeyFile

			startingContent, observedFiles, err := c.AddDefaultRotationToConfig(config, []byte("test-content"))
			if err != nil {
				t.Fatalf("AddDefaultRotationToConfig failed: %v", err)
			}

			if tt.expectGenerated {
				if config.ServingInfo.CertFile == "" {
					t.Error("expected CertFile to be generated")
				}
				if config.ServingInfo.KeyFile == "" {
					t.Error("expected KeyFile to be generated")
				}
			} else {
				if config.ServingInfo.CertFile != tt.existingCertFile {
					t.Errorf("expected CertFile to remain %q, got %q", tt.existingCertFile, config.ServingInfo.CertFile)
				}
				if config.ServingInfo.KeyFile != tt.existingKeyFile {
					t.Errorf("expected KeyFile to remain %q, got %q", tt.existingKeyFile, config.ServingInfo.KeyFile)
				}
			}

			if len(observedFiles) != tt.expectObservedLen {
				t.Errorf("expected %d observed files, got %d: %v", tt.expectObservedLen, len(observedFiles), observedFiles)
			}

			// Config file should be in observed files if provided
			if tt.configFile != "" {
				found := false
				for _, f := range observedFiles {
					if f == configFile {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected config file %q in observed files", configFile)
				}

				// Config file should be in starting content
				if _, ok := startingContent[configFile]; !ok {
					t.Error("expected config file in starting content")
				}
			}
		})
	}
}

func TestConfig(t *testing.T) {
	tests := []struct {
		name           string
		configContent  string
		expectError    bool
		expectNilUnstr bool
		validateConfig func(*testing.T, *operatorv1alpha1.GenericOperatorConfig)
	}{
		{
			name:           "no config file",
			expectNilUnstr: true,
			validateConfig: func(t *testing.T, config *operatorv1alpha1.GenericOperatorConfig) {
				if config == nil {
					t.Error("expected config to be initialized")
				}
			},
		},
		{
			name: "valid config file",
			configContent: `
apiVersion: operator.openshift.io/v1alpha1
kind: GenericOperatorConfig
servingInfo:
  bindAddress: https://0.0.0.0:8443
leaderElection:
  leaseDuration: 90s
`,
			expectNilUnstr: false,
			validateConfig: func(t *testing.T, config *operatorv1alpha1.GenericOperatorConfig) {
				if config.ServingInfo.BindAddress != "https://0.0.0.0:8443" {
					t.Errorf("expected BindAddress to be parsed correctly, got %q", config.ServingInfo.BindAddress)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ControllerCommandConfig{
				componentName: "test",
				basicFlags:    &ControllerFlags{},
			}

			if tt.configContent != "" {
				tmpDir := t.TempDir()
				configFile := filepath.Join(tmpDir, "config.yaml")
				if err := os.WriteFile(configFile, []byte(tt.configContent), 0644); err != nil {
					t.Fatalf("failed to write config file: %v", err)
				}
				c.basicFlags.ConfigFile = configFile
			}

			unstructured, config, content, err := c.Config()

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.expectNilUnstr && unstructured != nil {
				t.Error("expected unstructured to be nil")
			}
			if !tt.expectNilUnstr && unstructured == nil {
				t.Error("expected unstructured to be non-nil")
			}

			if tt.validateConfig != nil {
				tt.validateConfig(t, config)
			}

			if tt.configContent != "" && content == nil {
				t.Error("expected content to be set when config file exists")
			}
		})
	}
}
