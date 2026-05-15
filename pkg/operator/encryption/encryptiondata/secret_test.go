package encryptiondata_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
)

func TestFromSecretPluginDataKeyHandling(t *testing.T) {
	baseSecret := func(t *testing.T) map[string][]byte {
		t.Helper()
		cfg := &encryptiondata.Config{
			Encryption: &apiserverconfigv1.EncryptionConfiguration{
				Resources: []apiserverconfigv1.ResourceConfiguration{{
					Resources: []string{"secrets"},
				}},
			},
		}
		secret, err := encryptiondata.ToSecret("ns", "name", cfg)
		if err != nil {
			t.Fatalf("failed to create base secret: %v", err)
		}
		return secret.Data
	}

	tests := []struct {
		name      string
		extraKeys map[string][]byte
		wantError bool
	}{
		{
			name: "no plugin config keys",
		},
		{
			name:      "non-integer suffix is rejected",
			extraKeys: map[string][]byte{"kms-plugin-config-abc": {}},
			wantError: true,
		},
		{
			name:      "negative suffix is rejected",
			extraKeys: map[string][]byte{"kms-plugin-config--1": {}},
			wantError: true,
		},
		{
			name:      "empty suffix is ignored",
			extraKeys: map[string][]byte{"kms-plugin-config-": {}},
		},
		{
			name:      "unrelated keys are ignored",
			extraKeys: map[string][]byte{"some-other-key": {}},
		},
		{
			name:      "empty string key is ignored",
			extraKeys: map[string][]byte{"": {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := baseSecret(t)
			for k, v := range tt.extraKeys {
				data[k] = v
			}
			secret := &corev1.Secret{Data: data}
			_, err := encryptiondata.FromSecret(secret)
			if tt.wantError && err == nil {
				t.Fatal("expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestToSecretPluginKeyIDValidation(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		wantError bool
	}{
		{
			name:  "valid keyID",
			keyID: "1",
		},
		{
			name:  "valid large keyID",
			keyID: "42",
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
			cfg := &encryptiondata.Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
					}},
				},
				KMSPlugins: map[string]configv1.KMSPluginConfig{
					tt.keyID: {},
				},
			}
			_, err := encryptiondata.ToSecret("ns", "name", cfg)
			if tt.wantError && err == nil {
				t.Fatalf("expected error for keyID %q", tt.keyID)
			}
			if !tt.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestExtractUniqueAndSortedKMSConfigurations(t *testing.T) {
	timeout := &metav1.Duration{Duration: 10 * time.Second}

	tests := []struct {
		name      string
		cfg       *encryptiondata.Config
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
			cfg:       &encryptiondata.Config{},
			wantError: true,
		},
		{
			name: "empty provider list returns empty slice",
			cfg: &encryptiondata.Config{
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
			cfg: &encryptiondata.Config{
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
			cfg: &encryptiondata.Config{
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
			cfg: &encryptiondata.Config{
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
			cfg: &encryptiondata.Config{
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
			cfg: &encryptiondata.Config{
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
			cfg: &encryptiondata.Config{
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
			got, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(tt.cfg)
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
