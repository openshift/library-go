package encryptionconfig

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
)

func TestToEncryptionState(t *testing.T) {
	scenarios := []struct {
		name   string
		input  *apiserverconfigv1.EncryptionConfiguration
		output map[schema.GroupResource]state.GroupResourceState
	}{
		// scenario 1
		{
			name: "single write key",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := encryptiontesting.EncryptionKeysResourceTuple{
					Resource: "secrets",
					Keys: []apiserverconfigv1.Key{
						{
							Name:   "34",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},
					},
				}
				ec := encryptiontesting.CreateEncryptionCfgWithWriteKey([]encryptiontesting.EncryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34,
					},
					ReadKeys: []state.KeyState{{
						Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34,
					}},
				},
			},
		},

		// scenario 2
		{
			name: "multiple keys",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := encryptiontesting.EncryptionKeysResourceTuple{
					Resource: "secrets",
					Keys: []apiserverconfigv1.Key{
						{
							Name:   "34",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},
						{
							Name:   "33",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},
					},
				}
				ec := encryptiontesting.CreateEncryptionCfgWithWriteKey([]encryptiontesting.EncryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
						{Key: apiserverconfigv1.Key{Name: "33", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 33},
					},
				},
			},
		},

		// scenario 3
		{
			name: "single write key multiple resources",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := []encryptiontesting.EncryptionKeysResourceTuple{
					{
						Resource: "secrets",
						Keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
						},
					},

					{
						Resource: "configmaps",
						Keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
						},
					},
				}
				ec := encryptiontesting.CreateEncryptionCfgWithWriteKey(keysRes)
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
					},
				},
				{Group: "", Resource: "configmaps"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
					},
				},
			},
		},

		// scenario 4
		{
			name: "multiple keys and multiple resources",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := []encryptiontesting.EncryptionKeysResourceTuple{
					{
						Resource: "secrets",
						Keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
							{
								Name:   "33",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
						},
					},

					{
						Resource: "configmaps",
						Keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
							{
								Name:   "33",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},
						},
					},
				}
				ec := encryptiontesting.CreateEncryptionCfgWithWriteKey(keysRes)
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
						{Key: apiserverconfigv1.Key{Name: "33", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 33},
					},
				},
				{Group: "", Resource: "configmaps"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
						{Key: apiserverconfigv1.Key{Name: "33", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 33},
					},
				},
			},
		},

		// scenario 5
		{
			name: "single read key",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				ec := encryptiontesting.CreateEncryptionCfgNoWriteKey("34", "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=", "secrets")
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
					},
				},
			},
		},

		// scenario 6
		{
			name: "single read key multiple resources",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				ec := encryptiontesting.CreateEncryptionCfgNoWriteKey("34", "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=", "secrets", "configmaps")
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
					},
				},
				{Group: "", Resource: "configmaps"}: {
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
					},
				},
			},
		},

		// scenario 7
		{
			name: "turn off encryption for single resource",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := encryptiontesting.EncryptionKeysResourceTuple{
					Resource: "secrets",
					Keys: []apiserverconfigv1.Key{
						{
							Name:   "34",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},
						{
							Name:   "35",
							Secret: newFakeIdentityEncodedKeyForTest(),
						},
					},
					Modes: []string{"aescbc", "aesgcm"},
				}
				ec := encryptiontesting.CreateEncryptionCfgNoWriteKeyMultipleReadKeys([]encryptiontesting.EncryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, Mode: "identity", Generation: 35,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, Mode: "identity", Generation: 35},
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
					},
				},
			},
		},

		// scenario 8
		{
			name: "turn off encryption for multiple resources",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := []encryptiontesting.EncryptionKeysResourceTuple{
					{
						Resource: "secrets",
						Keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},

							// stateToProviders puts "fakeIdentityProvider" as last
							{
								Name:   "35",
								Secret: newFakeIdentityEncodedKeyForTest(),
							},
						},
						Modes: []string{"aescbc", "aesgcm"},
					},

					{
						Resource: "configmaps",
						Keys: []apiserverconfigv1.Key{
							{
								Name:   "34",
								Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
							},

							// stateToProviders puts "fakeIdentityProvider" as last
							{
								Name:   "35",
								Secret: newFakeIdentityEncodedKeyForTest(),
							},
						},
						Modes: []string{"aescbc", "aesgcm"},
					},
				}
				ec := encryptiontesting.CreateEncryptionCfgNoWriteKeyMultipleReadKeys(keysRes)
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, Mode: "identity", Generation: 35,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, Mode: "identity", Generation: 35},
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
					},
				},

				{Group: "", Resource: "configmaps"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, Mode: "identity", Generation: 35,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "35", Secret: newFakeIdentityEncodedKeyForTest()}, Mode: "identity", Generation: 35},
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
					},
				},
			},
		},

		// scenario 9
		// TODO: encryption on after being off

		// scenario 10
		{
			name: "aes-gcm write key and aes-cbc read key",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := encryptiontesting.EncryptionKeysResourceTuple{
					Resource: "secrets",
					Keys: []apiserverconfigv1.Key{
						{
							Name:   "35",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},
						{
							Name:   "34",
							Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc=",
						},
					},
					Modes: []string{"aesgcm", "aescbc"},
				}
				ec := encryptiontesting.CreateEncryptionCfgWithWriteKey([]encryptiontesting.EncryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					WriteKey: state.KeyState{
						Key: apiserverconfigv1.Key{Name: "35", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aesgcm", Generation: 35,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "35", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aesgcm", Generation: 35},
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
					},
				},
			},
		},

		// feature-gated KMS (external managed keys)

		// scenario 11
		{
			name: "KMS enabled",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := encryptiontesting.EncryptionKeysResourceTuple{
					Resource: "secrets",
					Keys:     []apiserverconfigv1.Key{{Name: "1"}}, // kms key generation id
					Modes:    []string{"KMS"},
				}
				ec := encryptiontesting.CreateEncryptionCfgWithWriteKey([]encryptiontesting.EncryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					WriteKey: state.KeyState{
						Mode:          state.KMS,
						KMSPluginHash: "foocloudhash",
						KMSConfig:     nil,
						Generation:    1,
					},
					ReadKeys: []state.KeyState{
						{Mode: state.KMS, KMSPluginHash: "foocloudhash", KMSConfig: nil, Generation: 1},
					},
				},
			},
		},
		// scenario 12
		{
			name: "KMS enabled after aescbc",
			input: func() *apiserverconfigv1.EncryptionConfiguration {
				keysRes := encryptiontesting.EncryptionKeysResourceTuple{
					Resource: "secrets",
					Keys: []apiserverconfigv1.Key{
						{Name: "1"}, // kms key generation id
						{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="},
					},
					Modes: []string{"KMS", "aescbc"},
				}
				ec := encryptiontesting.CreateEncryptionCfgWithWriteKey([]encryptiontesting.EncryptionKeysResourceTuple{keysRes})
				return ec
			}(),
			output: map[schema.GroupResource]state.GroupResourceState{
				{Group: "", Resource: "secrets"}: {
					WriteKey: state.KeyState{
						Mode:          state.KMS,
						KMSPluginHash: "foocloudhash",
						KMSConfig:     nil,
						Generation:    1,
					},
					ReadKeys: []state.KeyState{
						{Key: apiserverconfigv1.Key{Name: "34", Secret: "MTcxNTgyYTBmY2Q2YzVmZGI2NWNiZjVhM2U5MjQ5ZDc="}, Mode: "aescbc", Generation: 34},
						{Mode: state.KMS, KMSPluginHash: "foocloudhash", KMSConfig: nil, Generation: 1},
					},
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			actualOutput, _ := ToEncryptionState(scenario.input, nil)

			if len(actualOutput) != len(scenario.output) {
				t.Fatalf("expected to get %d GR, got %d", len(scenario.output), len(actualOutput))
			}
			for actualGR, actualKeys := range actualOutput {
				if _, ok := scenario.output[actualGR]; !ok {
					t.Fatalf("unexpected GR %v found", actualGR)
				}
				expectedKeys, _ := scenario.output[actualGR]
				if !cmp.Equal(expectedKeys.WriteKey, actualKeys.WriteKey, cmp.AllowUnexported(state.GroupResourceState{}.WriteKey)) {
					t.Fatal(fmt.Errorf("%s", cmp.Diff(expectedKeys.WriteKey, actualKeys.WriteKey, cmp.AllowUnexported(state.GroupResourceState{}.WriteKey))))
				}
				if !cmp.Equal(expectedKeys.ReadKeys, actualKeys.ReadKeys, cmp.AllowUnexported(state.GroupResourceState{}.WriteKey)) {
					t.Fatal(fmt.Errorf("%s", cmp.Diff(expectedKeys.ReadKeys, actualKeys.ReadKeys, cmp.AllowUnexported(state.GroupResourceState{}.WriteKey))))
				}
			}
		})
	}
}

func TestFromEncryptionState(t *testing.T) {
	// sorted list of GRs and their respective hash
	allGRs := []schema.GroupResource{
		{Group: "", Resource: "configmaps"},
		{Group: "oauth.openshift.io", Resource: "oauthaccesstokens"},
		{Group: "oauth.openshift.io", Resource: "oauthauthorizetokens"},
		{Group: "route.openshift.io", Resource: "routes"},
		{Group: "", Resource: "secrets"},
	}
	knownGRHashes := []string{"25159cbc", "821b2f37", "be516df8", "f6269648", "b7d9e546"}

	scenarios := []struct {
		name       string
		grs        []schema.GroupResource
		targetNs   string
		writeKeyIn *corev1.Secret
		readKeysIn []*corev1.Secret
		output     []apiserverconfigv1.ResourceConfiguration
		makeOutput func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration
	}{
		// scenario 1
		{
			name:       "turn off encryption for single resource",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}},
			targetNs:   "kms",
			writeKeyIn: encryptiontesting.CreateEncryptionKeySecretWithRawKeyWithMode("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 3, newFakeIdentityKeyForTest(), "identity"),
			readKeysIn: []*corev1.Secret{
				encryptiontesting.CreateEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 2, []byte("61def964fb967f5d7c44a2af8dab6865")),
				encryptiontesting.CreateExpiredMigratedEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 1, []byte("61def964fb967f5d7c44a2af8dab6865")),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{AESGCM: keyToAESConfiguration(writeKey)},
				}
				return []apiserverconfigv1.ResourceConfiguration{rs}
			},
		},

		// scenario 2
		{
			name:       "order of the keys is preserved, the write key comes first, then the read keys finally the identity comes last",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}},
			targetNs:   "kms",
			writeKeyIn: encryptiontesting.CreateEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 3, []byte("16f87d5793a3cb726fb9be7ef8211821")),
			readKeysIn: []*corev1.Secret{
				encryptiontesting.CreateEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 2, []byte("558bf68d6d8ab5dd819eec02901766c1")),
				encryptiontesting.CreateExpiredMigratedEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 1, []byte("61def964fb967f5d7c44a2af8dab6865")),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{
					{AESCBC: keyToAESConfiguration(writeKey)},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
				}
				return []apiserverconfigv1.ResourceConfiguration{rs}
			},
		},

		// scenario 3
		{
			name:     "the identity comes first up when there are no keys",
			grs:      []schema.GroupResource{{Group: "", Resource: "secrets"}},
			targetNs: "kms",
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{{Identity: &apiserverconfigv1.IdentityConfiguration{}}}
				return []apiserverconfigv1.ResourceConfiguration{rs}
			},
		},

		// scenario 4
		{
			name:       "order of the keys is preserved, the write key comes first, then the read keys finally the identity comes last - multiple resources",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}},
			targetNs:   "kms",
			writeKeyIn: encryptiontesting.CreateEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 3, []byte("16f87d5793a3cb726fb9be7ef8211821")),
			readKeysIn: []*corev1.Secret{
				encryptiontesting.CreateEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 2, []byte("558bf68d6d8ab5dd819eec02901766c1")),
				encryptiontesting.CreateExpiredMigratedEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 1, []byte("61def964fb967f5d7c44a2af8dab6865")),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rc := apiserverconfigv1.ResourceConfiguration{}
				rc.Resources = []string{"configmaps"}
				rc.Providers = []apiserverconfigv1.ProviderConfiguration{
					{AESCBC: keyToAESConfiguration(writeKey)},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
				}

				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{
					{AESCBC: keyToAESConfiguration(writeKey)},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
				}

				return []apiserverconfigv1.ResourceConfiguration{rc, rs}
			},
		},

		// scenario 5
		{
			name:       "turn off encryption for multiple resources",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}},
			targetNs:   "kms",
			writeKeyIn: encryptiontesting.CreateEncryptionKeySecretWithRawKeyWithMode("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 3, newFakeIdentityKeyForTest(), "identity"),
			readKeysIn: []*corev1.Secret{
				encryptiontesting.CreateEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "", Resource: "configmaps"}}, 2, []byte("61def964fb967f5d7c44a2af8dab6865")),
				encryptiontesting.CreateExpiredMigratedEncryptionKeySecretWithRawKey("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 1, []byte("61def964fb967f5d7c44a2af8dab6865")),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rc := apiserverconfigv1.ResourceConfiguration{}
				rc.Resources = []string{"configmaps"}
				rc.Providers = []apiserverconfigv1.ProviderConfiguration{
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{AESGCM: keyToAESConfiguration(writeKey)},
				}

				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}
				rs.Providers = []apiserverconfigv1.ProviderConfiguration{
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
					{AESCBC: keyToAESConfiguration(readKeys[0])},
					{AESCBC: keyToAESConfiguration(readKeys[1])},
					{AESGCM: keyToAESConfiguration(writeKey)},
				}
				return []apiserverconfigv1.ResourceConfiguration{rc, rs}
			},
		},

		// scenario 6
		// TODO: encryption on after being off

		// scenario 7: KMS for secrets encryption
		{
			name:       "turn on KMS for single resource",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}},
			targetNs:   "kms",
			writeKeyIn: encryptiontesting.CreateEncryptionKeySecretForKMS("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 1, "KMS"),
			readKeysIn: []*corev1.Secret{
				encryptiontesting.CreateEncryptionKeySecretForKMS("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}}, 1, "KMS"),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rs := apiserverconfigv1.ResourceConfiguration{}
				rs.Resources = []string{"secrets"}

				rs.Providers = []apiserverconfigv1.ProviderConfiguration{
					{
						KMS: &apiserverconfigv1.KMSConfiguration{
							// format: "kms-%d-%s-%s", generation, kmsPluginHash, grHash; generation=keyGenerationId, kmsPluginHash="foocloudhash" from test setting, grHash=32FNV1a-hash("secrets")
							Name: "kms-1-foocloudhash-b7d9e546",
							// format: "unix:///var/kube-kms/%s/socket.sock", kmsPluginHash; kmsPluginHash="foocloudhash"
							Endpoint: "unix:///var/kube-kms/foocloudhash/socket.sock",

							APIVersion: "v2",
							Timeout:    &metav1.Duration{Duration: 5 * time.Second},
						},
					},
					{Identity: &apiserverconfigv1.IdentityConfiguration{}},
				}
				return []apiserverconfigv1.ResourceConfiguration{rs}
			},
		},
		// scenario 8: another KMS propagation with secrets and routes
		{
			name:       "turn on KMS for two resources",
			grs:        []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "route.openshift.io", Resource: "routes"}},
			targetNs:   "kms",
			writeKeyIn: encryptiontesting.CreateEncryptionKeySecretForKMS("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "route.openshift.io", Resource: "routes"}}, 1, "KMS"),
			readKeysIn: []*corev1.Secret{
				encryptiontesting.CreateEncryptionKeySecretForKMS("kms", []schema.GroupResource{{Group: "", Resource: "secrets"}, {Group: "route.openshift.io", Resource: "routes"}}, 1, "KMS"),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				rs1 := apiserverconfigv1.ResourceConfiguration{
					Resources: []string{"secrets"},
					Providers: []apiserverconfigv1.ProviderConfiguration{
						{
							KMS: &apiserverconfigv1.KMSConfiguration{
								// format: "kms-%d-%s-%s", generation, kmsPluginHash, grHash; generation=keyGenerationId, kmsPluginHash="foocloudhash" from test setting, grHash=32FNV1a-hash("secrets")
								Name: "kms-1-foocloudhash-b7d9e546",
								// format: "unix:///var/kube-kms/%s/socket.sock", kmsPluginHash; kmsPluginHash="foocloudhash"
								Endpoint: "unix:///var/kube-kms/foocloudhash/socket.sock",

								APIVersion: "v2",
								Timeout:    &metav1.Duration{Duration: 5 * time.Second},
							},
						},
						{Identity: &apiserverconfigv1.IdentityConfiguration{}},
					},
				}

				rs2 := apiserverconfigv1.ResourceConfiguration{
					Resources: []string{"routes.route.openshift.io"},
					Providers: []apiserverconfigv1.ProviderConfiguration{
						{
							KMS: &apiserverconfigv1.KMSConfiguration{
								// format: "kms-%d-%s-%s", generation, kmsPluginHash, grHash; generation=keyGenerationId, kmsPluginHash="foocloudhash" from test setting, grHash=32FNV1a-hash("routes.route.openshift.io")
								Name: "kms-1-foocloudhash-f6269648",
								// format: "unix:///var/kube-kms/%s/socket.sock", kmsPluginHash; kmsPluginHash="foocloudhash"
								Endpoint: "unix:///var/kube-kms/foocloudhash/socket.sock",

								APIVersion: "v2",
								Timeout:    &metav1.Duration{Duration: 5 * time.Second},
							},
						},
						{Identity: &apiserverconfigv1.IdentityConfiguration{}},
					},
				}

				// when sorted by resource name, "routes" come before "secrets"
				return []apiserverconfigv1.ResourceConfiguration{rs2, rs1}
			},
		},
		// scenario 9: full KMS applied with secrets, configmaps, routes, oauth resources following an aescbc encryption
		{
			name:       "switch to KMS encryption after aescbc encryption was used",
			grs:        allGRs,
			targetNs:   "kms",
			writeKeyIn: encryptiontesting.CreateEncryptionKeySecretForKMS("kms", allGRs, 1, "KMS"),
			readKeysIn: []*corev1.Secret{
				encryptiontesting.CreateEncryptionKeySecretWithRawKey("kms", allGRs, 2, []byte("61def964fb967f5d7c44a2af8dab6865")),
			},
			makeOutput: func(writeKey *corev1.Secret, readKeys []*corev1.Secret) []apiserverconfigv1.ResourceConfiguration {
				res := make([]apiserverconfigv1.ResourceConfiguration, len(allGRs))

				for i, gr := range allGRs {
					res[i] = apiserverconfigv1.ResourceConfiguration{
						Resources: []string{gr.String()},
						Providers: []apiserverconfigv1.ProviderConfiguration{
							{
								KMS: &apiserverconfigv1.KMSConfiguration{
									// format: "kms-%d-%s-%s", generation, kmsPluginHash, grHash; generation=keyGenerationId, kmsPluginHash="foocloudhash" from test setting, grHash=32FNV1a-hash(grString)
									Name: "kms-1-foocloudhash-" + knownGRHashes[i],
									// format: "unix:///var/kube-kms/%s/socket.sock", kmsPluginHash; kmsPluginHash="foocloudhash"
									Endpoint: "unix:///var/kube-kms/foocloudhash/socket.sock",

									APIVersion: "v2",
									Timeout:    &metav1.Duration{Duration: 5 * time.Second},
								},
							},
							{AESCBC: keyToAESConfiguration(readKeys[0])},
							{Identity: &apiserverconfigv1.IdentityConfiguration{}},
						},
					}
				}

				return res
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {

			readKeyStatesIn := make([]state.KeyState, 0, len(scenario.readKeysIn))
			for _, s := range scenario.readKeysIn {
				ks, err := secrets.ToKeyState(s)
				if err != nil {
					t.Fatal(err)
				}
				readKeyStatesIn = append(readKeyStatesIn, ks)
			}

			var writeKeyStateIn state.KeyState
			if scenario.writeKeyIn != nil {
				var err error
				writeKeyStateIn, err = secrets.ToKeyState(scenario.writeKeyIn)
				if err != nil {
					t.Fatal(err)
				}
			}

			grState := map[schema.GroupResource]state.GroupResourceState{}
			for _, gr := range scenario.grs {
				ks := state.GroupResourceState{
					ReadKeys: readKeyStatesIn,
					WriteKey: writeKeyStateIn,
				}
				grState[gr] = ks
			}
			actualOutput := FromEncryptionState(grState)
			expectedOutput := scenario.makeOutput(scenario.writeKeyIn, scenario.readKeysIn)

			if !cmp.Equal(expectedOutput, actualOutput.Resources) {
				t.Fatal(fmt.Errorf("%s", cmp.Diff(expectedOutput, actualOutput.Resources)))
			}
		})
	}
}

func keyToAESConfiguration(key *corev1.Secret) *apiserverconfigv1.AESConfiguration {
	id, ok := state.NameToKeyID(key.Name)
	if !ok {
		panic(fmt.Sprintf("invalid test secret name %q", key.Name))
	}
	return &apiserverconfigv1.AESConfiguration{
		Keys: []apiserverconfigv1.Key{
			{
				Name:   fmt.Sprintf("%d", id),
				Secret: base64.StdEncoding.EncodeToString(key.Data[secrets.EncryptionSecretKeyDataKey]),
			},
		},
	}
}

func newFakeIdentityEncodedKeyForTest() string {
	return "AAAAAAAAAAAAAAAAAAAAAA=="
}

func newFakeIdentityKeyForTest() []byte {
	return make([]byte, 16)
}
