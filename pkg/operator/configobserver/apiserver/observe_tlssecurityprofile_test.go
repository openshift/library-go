package apiserver

import (
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"

	"github.com/openshift/library-go/pkg/operator/events"
)

func TestObserveTLSSecurityProfile(t *testing.T) {
	existingTLSVersion := "VersionTLS11"
	existingCipherSuites := []interface{}{"DES-CBC3-SHA"}

	tests := []struct {
		name                  string
		config                *configv1.TLSSecurityProfile
		expectedMinTLSVersion string
		expectedSuites        []string
	}{
		{
			name:                  "NoAPIServerConfig",
			config:                nil,
			expectedMinTLSVersion: "VersionTLS12",
			expectedSuites: []string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
				"TLS_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			},
		},
		{
			name: "ModernCrypto",
			config: &configv1.TLSSecurityProfile{
				Type:   configv1.TLSProfileModernType,
				Modern: &configv1.ModernTLSProfile{},
			},
			expectedMinTLSVersion: "VersionTLS13",
			expectedSuites: []string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
				"TLS_CHACHA20_POLY1305_SHA256",
			},
		},
		{
			name: "OldCrypto",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
				Old:  &configv1.OldTLSProfile{},
			},
			expectedMinTLSVersion: "VersionTLS10",
			expectedSuites: []string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
				"TLS_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
				"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
				"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
				"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
				"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
				"TLS_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_RSA_WITH_AES_128_CBC_SHA256",
				"TLS_RSA_WITH_AES_128_CBC_SHA",
				"TLS_RSA_WITH_AES_256_CBC_SHA",
				"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, useAPIServerArgs := range []bool{false, true} {
				minTLSVersionPath := []string{"servingInfo", "minTLSVersion"}
				cipherSuitesPath := []string{"servingInfo", "cipherSuites"}
				name := "FromServingInfo"
				if useAPIServerArgs {
					minTLSVersionPath = []string{"apiServerArguments", "tls-min-version"}
					cipherSuitesPath = []string{"apiServerArguments", "tls-cipher-suites"}
					name = "FromAPIServerArguments"
				}
				t.Run(name, func(t *testing.T) {
					indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
					if tt.config != nil {
						if err := indexer.Add(&configv1.APIServer{
							ObjectMeta: metav1.ObjectMeta{
								Name: "cluster",
							},
							Spec: configv1.APIServerSpec{
								TLSSecurityProfile: tt.config,
							},
						}); err != nil {
							t.Fatal(err)
						}
					}
					listers := testLister{
						apiLister: configlistersv1.NewAPIServerLister(indexer),
					}

					existingConfig := map[string]interface{}{}
					if err := unstructured.SetNestedField(existingConfig, existingTLSVersion, minTLSVersionPath...); err != nil {
						t.Fatalf("couldn't set existing min TLS version: %v", err)
					}
					if err := unstructured.SetNestedField(existingConfig, existingCipherSuites, cipherSuitesPath...); err != nil {
						t.Fatalf("couldn't set existing cipher suites: %v", err)
					}

					var result map[string]interface{}
					var errs []error
					if useAPIServerArgs {
						result, errs = ObserveTLSSecurityProfileToArguments(listers, events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())), existingConfig)
					} else {
						result, errs = ObserveTLSSecurityProfile(listers, events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())), existingConfig)
					}
					if len(errs) > 0 {
						t.Errorf("expected 0 errors, got %v", errs)
					}

					gotMinTLSVersion, _, err := unstructured.NestedString(result, minTLSVersionPath...)
					if err != nil {
						t.Errorf("couldn't get minTLSVersion from the returned object: %v", err)
					}

					gotSuites, _, err := unstructured.NestedStringSlice(result, cipherSuitesPath...)
					if err != nil {
						t.Errorf("couldn't get cipherSuites from the returned object: %v", err)
					}

					if !reflect.DeepEqual(gotSuites, tt.expectedSuites) {
						t.Errorf("got cipherSuites = %v, expected %v", gotSuites, tt.expectedSuites)
					}
					if gotMinTLSVersion != tt.expectedMinTLSVersion {
						t.Errorf("got minTlSVersion = %v, expected %v", gotMinTLSVersion, tt.expectedMinTLSVersion)
					}
				})
			}
		})
	}
}

func TestObserveTLSSecurityProfileWithGroupPaths(t *testing.T) {
	defaultGroups := []string{"X25519MLKEM768", "X25519", "secp256r1", "secp384r1"}

	tests := []struct {
		name           string
		config         *configv1.TLSSecurityProfile
		expectedGroups []string
	}{
		{
			name:           "NoAPIServerConfig",
			config:         nil,
			expectedGroups: defaultGroups,
		},
		{
			name: "IntermediateProfile",
			config: &configv1.TLSSecurityProfile{
				Type:         configv1.TLSProfileIntermediateType,
				Intermediate: &configv1.IntermediateTLSProfile{},
			},
			expectedGroups: defaultGroups,
		},
		{
			name: "OldProfile",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
				Old:  &configv1.OldTLSProfile{},
			},
			expectedGroups: defaultGroups,
		},
		{
			name: "ModernProfile",
			config: &configv1.TLSSecurityProfile{
				Type:   configv1.TLSProfileModernType,
				Modern: &configv1.ModernTLSProfile{},
			},
			expectedGroups: defaultGroups,
		},
		{
			name: "CustomProfileNoGroups",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
					},
				},
			},
			expectedGroups: []string{},
		},
		{
			name: "CustomProfileWithGroups",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
						Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
					},
				},
			},
			expectedGroups: []string{"X25519", "secp256r1"},
		},
		{
			name: "CustomProfileWithUnknownGroup",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
						Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, "UnknownFutureGroup"},
					},
				},
			},
			expectedGroups: []string{"X25519"}, // "UnknownFutureGroup" must be dropped
		},
	}

	minTLSVersionPath := []string{"olmTLS", "minTLSVersion"}
	cipherSuitesPath := []string{"olmTLS", "cipherSuites"}
	groupsPath := []string{"olmTLS", "curvePreferences"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.config != nil {
				if err := indexer.Add(&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec:       configv1.APIServerSpec{TLSSecurityProfile: tt.config},
				}); err != nil {
					t.Fatal(err)
				}
			}
			listers := testLister{apiLister: configlistersv1.NewAPIServerLister(indexer)}

			result, errs := ObserveTLSSecurityProfileWithGroupPaths(
				listers,
				events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())),
				map[string]interface{}{},
				minTLSVersionPath,
				cipherSuitesPath,
				groupsPath,
			)
			if len(errs) > 0 {
				t.Errorf("expected 0 errors, got %v", errs)
			}

			gotGroups, _, err := unstructured.NestedStringSlice(result, groupsPath...)
			if err != nil {
				t.Errorf("couldn't get groups from result: %v", err)
			}

			if !reflect.DeepEqual(gotGroups, tt.expectedGroups) {
				t.Errorf("got groups = %v, expected %v", gotGroups, tt.expectedGroups)
			}

			// Verify the result is pruned to only the observed paths
			for k := range result {
				if k != "olmTLS" {
					t.Errorf("unexpected key %q in pruned result", k)
				}
			}
		})
	}
}
