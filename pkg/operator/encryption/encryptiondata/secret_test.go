package encryptiondata

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

func TestExtractUniqueAndSortedKMSConfigurations(t *testing.T) {
	timeout := &metav1.Duration{Duration: 10 * time.Second}

	tests := []struct {
		name      string
		cfg       *Config
		want      []*apiserverconfigv1.KMSConfiguration
		wantError bool
	}{
		{
			name:      "nil encryption returns error",
			cfg:       nil,
			wantError: true,
		},
		{
			name:      "nil encryption returns error",
			cfg:       &Config{},
			wantError: true,
		},
		{
			name: "empty provider list returns empty slice",
			cfg: &Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{},
					}},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{},
		},
		{
			name: "single resource single KMS provider",
			cfg: &Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{{
							KMS: &apiserverconfigv1.KMSConfiguration{
								APIVersion: "v2",
								Name:       "1_secrets",
								Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
								Timeout:    timeout,
							},
						}},
					}},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{{
				APIVersion: "v2",
				Name:       "1",
				Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
				Timeout:    timeout,
			}},
		},
		{
			name: "same keyID across resources is deduplicated",
			cfg: &Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{
						{
							Resources: []string{"secrets"},
							Providers: []apiserverconfigv1.ProviderConfiguration{{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							}},
						},
						{
							Resources: []string{"configmaps"},
							Providers: []apiserverconfigv1.ProviderConfiguration{{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_configmaps",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							}},
						},
					},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{{
				APIVersion: "v2",
				Name:       "1",
				Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
				Timeout:    timeout,
			}},
		},
		{
			name: "multiple keyIDs sorted descending",
			cfg: &Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{
							{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							},
							{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "3_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-3.sock",
									Timeout:    timeout,
								},
							},
							{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "2_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-2.sock",
									Timeout:    timeout,
								},
							},
						},
					}},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{
				{APIVersion: "v2", Name: "3", Endpoint: "unix:///var/run/kmsplugin/kms-3.sock", Timeout: timeout},
				{APIVersion: "v2", Name: "2", Endpoint: "unix:///var/run/kmsplugin/kms-2.sock", Timeout: timeout},
				{APIVersion: "v2", Name: "1", Endpoint: "unix:///var/run/kmsplugin/kms-1.sock", Timeout: timeout},
			},
		},
		{
			name: "non-KMS providers are skipped",
			cfg: &Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{
							{Identity: &apiserverconfigv1.IdentityConfiguration{}},
							{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							},
							{AESCBC: &apiserverconfigv1.AESConfiguration{Keys: []apiserverconfigv1.Key{{Name: "k", Secret: "s"}}}},
						},
					}},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{{
				APIVersion: "v2",
				Name:       "1",
				Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
				Timeout:    timeout,
			}},
		},
		{
			name: "mismatched duplicate keyID errors",
			cfg: &Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{
						{
							Resources: []string{"secrets"},
							Providers: []apiserverconfigv1.ProviderConfiguration{{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							}},
						},
						{
							Resources: []string{"configmaps"},
							Providers: []apiserverconfigv1.ProviderConfiguration{{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_configmaps",
									Endpoint:   "unix:///var/run/kmsplugin/kms-DIFFERENT.sock",
									Timeout:    timeout,
								},
							}},
						},
					},
				},
			},
			wantError: true,
		},
		{
			name: "invalid plugin name errors",
			cfg: &Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{{
							KMS: &apiserverconfigv1.KMSConfiguration{
								APIVersion: "v2",
								Name:       "no-underscore",
								Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
							},
						}},
					}},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractUniqueAndSortedKMSConfigurations(tt.cfg)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestKeyIDFromPluginConfigSecretDataKey(t *testing.T) {
	tests := []struct {
		name      string
		dataKey   string
		wantKeyID string
		wantFound bool
		wantError bool
	}{
		{
			name:      "valid key",
			dataKey:   "kms-plugin-config-1",
			wantKeyID: "1",
			wantFound: true,
		},
		{
			name:      "valid key with large ID",
			dataKey:   "kms-plugin-config-42",
			wantKeyID: "42",
			wantFound: true,
		},
		{
			name:    "encryption-config key",
			dataKey: "encryption-config",
		},
		{
			name:      "non-integer keyID",
			dataKey:   "kms-plugin-config-abc",
			wantError: true,
		},
		{
			name:    "missing keyID",
			dataKey: "kms-plugin-config-",
		},
		{
			name:    "empty string",
			dataKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, found, err := keyIDFromPluginConfigSecretDataKey(tt.dataKey)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if found != tt.wantFound {
				t.Fatalf("expected found=%v, got %v", tt.wantFound, found)
			}
			if found && keyID != tt.wantKeyID {
				t.Fatalf("expected keyID=%q, got %q", tt.wantKeyID, keyID)
			}
		})
	}
}

func TestToPluginConfigSecretDataKeyFor(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		wantKey   string
		wantError bool
	}{
		{
			name:    "valid keyID",
			keyID:   "1",
			wantKey: "kms-plugin-config-1",
		},
		{
			name:    "valid large keyID",
			keyID:   "42",
			wantKey: "kms-plugin-config-42",
		},
		{
			name:      "non-integer keyID",
			keyID:     "abc",
			wantError: true,
		},
		{
			name:      "empty keyID",
			keyID:     "",
			wantError: true,
		},
		{
			name:      "negative keyID",
			keyID:     "-1",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toPluginConfigSecretDataKeyFor(tt.keyID)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantKey {
				t.Fatalf("expected key=%q, got %q", tt.wantKey, got)
			}
		})
	}
}

func TestParseSecretDataKey(t *testing.T) {
	tests := []struct {
		name       string
		dataKey    string
		wantKeyID  string
		wantRawKey string
		wantFound  bool
		wantErr    bool
	}{
		{
			name:       "valid key",
			dataKey:    "kms-plugin-secret-vault-approle-secret_role-id-1",
			wantKeyID:  "1",
			wantRawKey: "vault-approle-secret_role-id",
			wantFound:  true,
		},
		{
			name:       "valid key with large keyID",
			dataKey:    "kms-plugin-secret-vault-approle-secret_secret-id-42",
			wantKeyID:  "42",
			wantRawKey: "vault-approle-secret_secret-id",
			wantFound:  true,
		},
		{
			name:    "encryption-config key ignored",
			dataKey: "encryption-config",
		},
		{
			name:    "plugin config key ignored",
			dataKey: "kms-plugin-config-1",
		},
		{
			name:    "empty string",
			dataKey: "",
		},
		{
			name:    "prefix only",
			dataKey: "kms-plugin-secret-",
		},
		{
			name:    "no dash after prefix",
			dataKey: "kms-plugin-secret-nodash",
		},
		{
			name:       "numeric segment in rawKey is not confused with keyID",
			dataKey:    "kms-plugin-secret-secret-a_port-8080-1",
			wantKeyID:  "1",
			wantRawKey: "secret-a_port-8080",
			wantFound:  true,
		},
		{
			name:       "flatKey ending with dash produces double dash before keyID",
			dataKey:    "kms-plugin-secret-secret-a_port-8080--1",
			wantKeyID:  "1",
			wantRawKey: "secret-a_port-8080-",
			wantFound:  true,
		},
		{
			name:    "non-numeric keyID",
			dataKey: "kms-plugin-secret-vault-approle-secret_role-id-abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, rawKey, found, err := parseSecretDataKey(tt.dataKey)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if found != tt.wantFound {
				t.Fatalf("found: got %v, want %v", found, tt.wantFound)
			}
			if found {
				if keyID != tt.wantKeyID {
					t.Errorf("keyID: got %q, want %q", keyID, tt.wantKeyID)
				}
				if rawKey != tt.wantRawKey {
					t.Errorf("rawKey: got %q, want %q", rawKey, tt.wantRawKey)
				}
			}
		})
	}
}
