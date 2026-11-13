package apiserver

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	configfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/configobserver"
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
	// The observer FIPS-filters groups, so expectations differ by runtime mode.
	// Under fips140=on, X25519MLKEM768 and X25519 are dropped; only the NIST
	// P-curves survive.
	fips := crypto.IsFIPSEnabled()
	pick := func(nonFIPS, fipsMode []string) []string {
		if fips {
			return fipsMode
		}
		return nonFIPS
	}
	defaultGroups := pick(
		[]string{"X25519MLKEM768", "X25519", "secp256r1", "secp384r1"},
		[]string{"secp256r1", "secp384r1"},
	)

	testCases := []struct {
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
			// Under FIPS the non-approved X25519 is dropped, leaving secp256r1.
			expectedGroups: pick([]string{"X25519", "secp256r1"}, []string{"secp256r1"}),
		},
		{
			// Under FIPS the ML-KEM hybrid is dropped, leaving an empty list.
			name: "CustomProfileMLKEMOnly",
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
						Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768},
					},
				},
			},
			expectedGroups: pick([]string{"X25519MLKEM768"}, []string{}),
		},
	}

	minTLSVersionPath := []string{"olmTLS", "minTLSVersion"}
	cipherSuitesPath := []string{"olmTLS", "cipherSuites"}
	groupsPath := []string{"olmTLS", "curvePreferences"}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tc.config != nil {
				if err := indexer.Add(&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
					Spec:       configv1.APIServerSpec{TLSSecurityProfile: tc.config},
				}); err != nil {
					t.Fatal(err)
				}
			}
			listers := testLister{apiLister: configlistersv1.NewAPIServerLister(indexer)}

			recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
			result, errs := ObserveTLSSecurityProfileWithGroupPaths(
				listers,
				recorder,
				map[string]interface{}{},
				minTLSVersionPath,
				cipherSuitesPath,
				groupsPath,
			)
			if len(errs) > 0 {
				t.Errorf("expected 0 errors, got %v", errs)
			}

			gotGroups, found, err := unstructured.NestedStringSlice(result, groupsPath...)
			if err != nil {
				t.Errorf("couldn't get groups from result: %v", err)
			}

			if len(tc.expectedGroups) == 0 {
				// An empty result is stored verbatim (an explicit []) so handshakes
				// fail rather than negotiating unrequested curves. The path must be
				// present but empty.
				if !found {
					t.Errorf("expected groups path to be present (as an empty list), but it was omitted")
				}
				if len(gotGroups) != 0 {
					t.Errorf("expected empty groups, got %v", gotGroups)
				}
				// A first reconcile with an empty result is nil-vs-empty, which
				// slices.Equal treats as unchanged: no spurious event.
				for _, ev := range recorder.Events() {
					if strings.Contains(ev.Message, "groups changed") {
						t.Errorf("unexpected groups-changed event for empty result: %q", ev.Message)
					}
				}
			} else {
				if !reflect.DeepEqual(gotGroups, tc.expectedGroups) {
					t.Errorf("got groups = %v, expected %v", gotGroups, tc.expectedGroups)
				}
				// A real (non-empty) first observation should report the change.
				sawEvent := false
				for _, ev := range recorder.Events() {
					if strings.Contains(ev.Message, "groups changed") {
						sawEvent = true
					}
				}
				if !sawEvent {
					t.Errorf("expected a groups-changed event for %v, got none", tc.expectedGroups)
				}
			}

			// The group observer must not clobber the sibling fields: minTLSVersion
			// and cipherSuites still have to be written alongside the groups.
			if _, found, _ := unstructured.NestedString(result, minTLSVersionPath...); !found {
				t.Errorf("minTLSVersion missing from result; group observation must not drop sibling fields")
			}
			if _, found, _ := unstructured.NestedStringSlice(result, cipherSuitesPath...); !found {
				t.Errorf("cipherSuites missing from result; group observation must not drop sibling fields")
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

// TestObserveTLSSecurityProfileWithGroupPathsSteadyState verifies that a
// reconcile whose observed non-empty groups already match the persisted groups
// emits NO "groups changed" event. The table test above always starts from an
// empty existingConfig (currentGroups == nil), so it only ever exercises the
// nil-vs-empty short-circuit and the "changed from nothing" path of slices.Equal;
// the "equal, non-empty -> suppress" branch — the actual point of the
// change-suppression logic — is never hit there. This test feeds a prior
// observation back in to exercise exactly that branch. It is FIPS-agnostic: the
// default profile yields a non-empty group list in both modes.
func TestObserveTLSSecurityProfileWithGroupPathsSteadyState(t *testing.T) {
	minTLSVersionPath := []string{"olmTLS", "minTLSVersion"}
	cipherSuitesPath := []string{"olmTLS", "cipherSuites"}
	groupsPath := []string{"olmTLS", "curvePreferences"}

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	listers := testLister{apiLister: configlistersv1.NewAPIServerLister(indexer)}

	// First reconcile from empty establishes the observed groups (and expectedly
	// fires a change event).
	first, errs := ObserveTLSSecurityProfileWithGroupPaths(
		listers,
		events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())),
		map[string]interface{}{},
		minTLSVersionPath, cipherSuitesPath, groupsPath,
	)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors on first reconcile: %v", errs)
	}
	observed, found, err := unstructured.NestedStringSlice(first, groupsPath...)
	if err != nil || !found || len(observed) == 0 {
		t.Fatalf("expected a non-empty observed groups list, got found=%v groups=%v err=%v", found, observed, err)
	}

	// Second reconcile fed the first result back in as existingConfig: groups are
	// unchanged, so no "groups changed" event must fire (slices.Equal returning
	// true for two equal non-empty slices).
	recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
	if _, errs = ObserveTLSSecurityProfileWithGroupPaths(
		listers, recorder, first, minTLSVersionPath, cipherSuitesPath, groupsPath,
	); len(errs) > 0 {
		t.Fatalf("unexpected errors on second reconcile: %v", errs)
	}
	for _, ev := range recorder.Events() {
		if strings.Contains(ev.Message, "groups changed") {
			t.Errorf("steady-state reconcile emitted a spurious groups-changed event: %q", ev.Message)
		}
	}
}

// tlsGroupToCurveIDOrDie converts a TLS group to curve ID as float64 or panics
func tlsGroupToCurveIDOrDie(group configv1.TLSGroup) float64 {
	curveID, ok := crypto.TLSGroupToCurveID(group)
	if !ok {
		panic("unrecognized TLS group: " + group)
	}
	return float64(curveID)
}

// groupsToCurvePrefs converts TLS groups to curve preference IDs as float64 (JSON unmarshal format)
func groupsToCurvePrefs(t *testing.T, groups []configv1.TLSGroup) []interface{} {
	result := make([]interface{}, len(groups))
	for i, group := range groups {
		result[i] = tlsGroupToCurveIDOrDie(group)
	}
	return result
}

// makeTLSProfile creates a TLS security profile for testing
func makeTLSProfile(profileType configv1.TLSProfileType, minTLSVersion configv1.TLSProtocolVersion, ciphers []string, groups []configv1.TLSGroup) *configv1.TLSSecurityProfile {
	profile := &configv1.TLSSecurityProfile{
		Type: profileType,
	}
	if profileType == configv1.TLSProfileCustomType {
		profile.Custom = &configv1.CustomTLSProfile{
			TLSProfileSpec: configv1.TLSProfileSpec{
				MinTLSVersion: minTLSVersion,
				Ciphers:       ciphers,
				Groups:        groups,
			},
		}
	}
	return profile
}

// setupTLSGroupsTest creates listers and recorder for testing ObserveTLSSecurityProfileWithGroupsConversion
func setupTLSGroupsTest(t *testing.T, apiServerTLSProfile *configv1.TLSSecurityProfile) (testLister, events.InMemoryRecorder) {
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: apiServerTLSProfile,
		},
	}

	configClient := configfake.NewSimpleClientset(apiServer)
	configInformers := configinformers.NewSharedInformerFactory(configClient, 0)

	if err := configInformers.Config().V1().APIServers().Informer().GetStore().Add(apiServer); err != nil {
		t.Fatalf("failed to add apiServer to informer store: %v", err)
	}

	listers := testLister{
		apiLister: configInformers.Config().V1().APIServers().Lister(),
	}
	recorder := events.NewInMemoryRecorder("test", clock.RealClock{})

	return listers, recorder
}

func TestObserveTLSSecurityProfileWithGroupsConversion(t *testing.T) {
	defaultProfile := configv1.TLSProfiles[crypto.DefaultTLSProfileType]
	oldProfile := configv1.TLSProfiles[configv1.TLSProfileOldType]
	modernProfile := configv1.TLSProfiles[configv1.TLSProfileModernType]

	tests := []struct {
		name                          string
		apiServerTLSProfile           *configv1.TLSSecurityProfile
		existingConfig                func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) map[string]interface{}
		expectedCurvePrefs            []interface{}
		expectedMinVersion            string
		expectedCipherSuites          []string
		expectError                   bool
		expectedErrorStrings          func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) []string
		mockObserveTLSSecurityProfile observeTLSSecurityProfileWithGroupPathsFunc
	}{
		{
			name:                 "missing TLS config defaults to default profile",
			apiServerTLSProfile:  nil,
			expectedCurvePrefs:   groupsToCurvePrefs(t, defaultProfile.Groups),
			expectedMinVersion:   string(defaultProfile.MinTLSVersion),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites(defaultProfile.Ciphers),
		},
		{
			name:                 "Old profile",
			apiServerTLSProfile:  makeTLSProfile(configv1.TLSProfileOldType, "", nil, nil),
			expectedCurvePrefs:   groupsToCurvePrefs(t, oldProfile.Groups),
			expectedMinVersion:   string(oldProfile.MinTLSVersion),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites(oldProfile.Ciphers),
		},
		{
			name:                 "Modern profile",
			apiServerTLSProfile:  makeTLSProfile(configv1.TLSProfileModernType, "", nil, nil),
			expectedCurvePrefs:   groupsToCurvePrefs(t, modernProfile.Groups),
			expectedMinVersion:   string(modernProfile.MinTLSVersion),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites(modernProfile.Ciphers),
		},
		{
			name: "Custom profile with specific groups",
			apiServerTLSProfile: makeTLSProfile(
				configv1.TLSProfileCustomType,
				configv1.VersionTLS12,
				[]string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				[]configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
			),
			expectedCurvePrefs: groupsToCurvePrefs(t, []configv1.TLSGroup{
				configv1.TLSGroupX25519,
				configv1.TLSGroupSecP256r1,
			}),
			expectedMinVersion: string(configv1.VersionTLS12),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites([]string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
			}),
		},
		{
			name:                "Unknown curve ID in existing curvePreferences before reconciling - silently dropped",
			apiServerTLSProfile: makeTLSProfile(configv1.TLSProfileModernType, "", nil, nil),
			existingConfig: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) map[string]interface{} {
				config := map[string]interface{}{}
				// For apiServerArguments paths, use string curve IDs. For servingInfo, use float64.
				if curvePreferencesPath[0] == "apiServerArguments" {
					unstructured.SetNestedSlice(config, []interface{}{
						fmt.Sprintf("%d", int64(tlsGroupToCurveIDOrDie(configv1.TLSGroupX25519))),
						"9999",
						fmt.Sprintf("%d", int64(tlsGroupToCurveIDOrDie(configv1.TLSGroupSecP256r1))),
					}, curvePreferencesPath...)
				} else {
					unstructured.SetNestedSlice(config, []interface{}{
						tlsGroupToCurveIDOrDie(configv1.TLSGroupX25519),
						float64(9999),
						tlsGroupToCurveIDOrDie(configv1.TLSGroupSecP256r1),
					}, curvePreferencesPath...)
				}
				return config
			},
			expectedCurvePrefs:   groupsToCurvePrefs(t, modernProfile.Groups),
			expectedMinVersion:   string(modernProfile.MinTLSVersion),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites(modernProfile.Ciphers),
		},
		{
			name:                "Corrupted minTLSVersion in existing config - all TLS settings still injected",
			apiServerTLSProfile: makeTLSProfile(configv1.TLSProfileModernType, "", nil, nil),
			existingConfig: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) map[string]interface{} {
				config := map[string]interface{}{}
				// Set as []interface{} instead of []string to avoid deep copy issues
				unstructured.SetNestedField(config, []interface{}{"not-a-string"}, minTLSVersionPath...)
				return config
			},
			expectedCurvePrefs:   groupsToCurvePrefs(t, modernProfile.Groups),
			expectedMinVersion:   string(modernProfile.MinTLSVersion),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites(modernProfile.Ciphers),
			expectError:          true,
			expectedErrorStrings: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) []string {
				pathStr := strings.Join(minTLSVersionPath, ".")
				return []string{
					fmt.Sprintf("failed to retrieve %v: .%s accessor error: [not-a-string] is of the type []interface {}, expected string", minTLSVersionPath, pathStr),
				}
			},
		},
		{
			name:                "Corrupted cipherSuites in existing config - all TLS settings still injected",
			apiServerTLSProfile: makeTLSProfile(configv1.TLSProfileModernType, "", nil, nil),
			existingConfig: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) map[string]interface{} {
				config := map[string]interface{}{}
				unstructured.SetNestedField(config, "not-a-slice", cipherSuitesPath...)
				return config
			},
			expectedCurvePrefs:   groupsToCurvePrefs(t, modernProfile.Groups),
			expectedMinVersion:   string(modernProfile.MinTLSVersion),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites(modernProfile.Ciphers),
			expectError:          true,
			expectedErrorStrings: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) []string {
				pathStr := strings.Join(cipherSuitesPath, ".")
				return []string{
					fmt.Sprintf("failed to retrieve %v: .%s accessor error: not-a-slice is of the type string, expected []interface{}", cipherSuitesPath, pathStr),
				}
			},
		},
		{
			name:                "Corrupted curvePreferences in existing config - all TLS settings still injected",
			apiServerTLSProfile: makeTLSProfile(configv1.TLSProfileModernType, "", nil, nil),
			existingConfig: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) map[string]interface{} {
				config := map[string]interface{}{}
				unstructured.SetNestedField(config, "not-a-slice", curvePreferencesPath...)
				return config
			},
			expectedCurvePrefs:   groupsToCurvePrefs(t, modernProfile.Groups),
			expectedMinVersion:   string(modernProfile.MinTLSVersion),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites(modernProfile.Ciphers),
			expectError:          true,
			expectedErrorStrings: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) []string {
				pathStr := strings.Join(curvePreferencesPath, ".")
				pathArray := fmt.Sprintf("[%s]", strings.Join(curvePreferencesPath, " "))
				return []string{
					fmt.Sprintf("failed to read curve preferences from %s: .%s accessor error: not-a-slice is of the type string, expected []interface{}", pathArray, pathStr),
					fmt.Sprintf(".%s accessor error: not-a-slice is of the type string, expected []interface{}", pathStr),
				}
			},
		},
		{
			name: "Unrecognized TLS groups - recognized groups converted, error for unrecognized",
			apiServerTLSProfile: makeTLSProfile(
				configv1.TLSProfileCustomType,
				configv1.VersionTLS12,
				[]string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				[]configv1.TLSGroup{configv1.TLSGroupX25519, "UnknownGroup", configv1.TLSGroupSecP256r1},
			),
			expectedCurvePrefs: groupsToCurvePrefs(t, []configv1.TLSGroup{
				configv1.TLSGroupX25519,
				configv1.TLSGroupSecP256r1,
			}),
			expectedMinVersion: string(configv1.VersionTLS12),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites([]string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
			}),
			expectError: true,
			expectedErrorStrings: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) []string {
				return []string{
					"unrecognized TLS groups: [UnknownGroup]",
				}
			},
		},
		{
			name: "Unrecognized TLS groups with corrupted curvePreferences - all errors reported, all TLS settings injected",
			apiServerTLSProfile: makeTLSProfile(
				configv1.TLSProfileCustomType,
				configv1.VersionTLS12,
				[]string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				[]configv1.TLSGroup{configv1.TLSGroupX25519, "UnknownGroup", configv1.TLSGroupSecP256r1},
			),
			existingConfig: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) map[string]interface{} {
				config := map[string]interface{}{}
				unstructured.SetNestedField(config, "not-a-slice", curvePreferencesPath...)
				return config
			},
			expectedCurvePrefs: groupsToCurvePrefs(t, []configv1.TLSGroup{
				configv1.TLSGroupX25519,
				configv1.TLSGroupSecP256r1,
			}),
			expectedMinVersion: string(configv1.VersionTLS12),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites([]string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
			}),
			expectError: true,
			expectedErrorStrings: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) []string {
				pathStr := strings.Join(curvePreferencesPath, ".")
				pathArray := fmt.Sprintf("[%s]", strings.Join(curvePreferencesPath, " "))
				return []string{
					fmt.Sprintf("failed to read curve preferences from %s: .%s accessor error: not-a-slice is of the type string, expected []interface{}", pathArray, pathStr),
					fmt.Sprintf(".%s accessor error: not-a-slice is of the type string, expected []interface{}", pathStr),
					"unrecognized TLS groups: [UnknownGroup]",
				}
			},
		},
		{
			name: "All TLS groups unrecognized - curvePreferences set to empty, minTLSVersion and cipherSuites set",
			apiServerTLSProfile: makeTLSProfile(
				configv1.TLSProfileCustomType,
				configv1.VersionTLS12,
				[]string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				[]configv1.TLSGroup{"UnknownGroup1", "UnknownGroup2", "UnknownGroup3"},
			),
			expectedCurvePrefs: []interface{}{},
			expectedMinVersion: string(configv1.VersionTLS12),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites([]string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
			}),
			expectError: true,
			expectedErrorStrings: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) []string {
				return []string{
					"unrecognized TLS groups: [UnknownGroup1 UnknownGroup2 UnknownGroup3]",
				}
			},
		},
		{
			name: "Custom profile with zero groups but existing curvePreferences - curvePreferences set to empty",
			apiServerTLSProfile: makeTLSProfile(
				configv1.TLSProfileCustomType,
				configv1.VersionTLS12,
				[]string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				[]configv1.TLSGroup{},
			),
			existingConfig: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) map[string]interface{} {
				config := map[string]interface{}{}
				// For apiServerArguments paths, use string curve IDs. For servingInfo, use float64.
				if curvePreferencesPath[0] == "apiServerArguments" {
					unstructured.SetNestedSlice(config, []interface{}{
						fmt.Sprintf("%d", int64(tlsGroupToCurveIDOrDie(configv1.TLSGroupX25519))),
						fmt.Sprintf("%d", int64(tlsGroupToCurveIDOrDie(configv1.TLSGroupSecP256r1))),
					}, curvePreferencesPath...)
				} else {
					unstructured.SetNestedSlice(config, []interface{}{
						tlsGroupToCurveIDOrDie(configv1.TLSGroupX25519),
						tlsGroupToCurveIDOrDie(configv1.TLSGroupSecP256r1),
					}, curvePreferencesPath...)
				}
				return config
			},
			expectedCurvePrefs: []interface{}{},
			expectedMinVersion: string(configv1.VersionTLS12),
			expectedCipherSuites: crypto.OpenSSLToIANACipherSuites([]string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
			}),
		},
		{
			name: "FIPS filtering - non-compliant groups filtered out, error reported",
			apiServerTLSProfile: makeTLSProfile(
				configv1.TLSProfileCustomType,
				configv1.VersionTLS12,
				[]string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				[]configv1.TLSGroup{
					configv1.TLSGroupX25519,         // Not FIPS compliant (filtered out)
					configv1.TLSGroupSecP256r1,      // FIPS compliant (kept)
					configv1.TLSGroupSecP384r1,      // FIPS compliant (kept)
					configv1.TLSGroupX25519MLKEM768, // Not FIPS compliant (filtered out)
				},
			),
			// Mock to simulate FIPS filtering
			mockObserveTLSSecurityProfile: func(
				listers configobserver.Listers,
				recorder events.Recorder,
				existingConfig map[string]interface{},
				minTLSVersionPath []string,
				cipherSuitesPath []string,
				groupsPath []string,
			) (map[string]interface{}, []error) {
				// Simulate FIPS filtering: only FIPS-compliant groups remain
				config := map[string]interface{}{}
				unstructured.SetNestedField(config, string(configv1.VersionTLS12), minTLSVersionPath...)
				unstructured.SetNestedStringSlice(config, []string{
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
				}, cipherSuitesPath...)
				unstructured.SetNestedStringSlice(config, []string{
					string(configv1.TLSGroupSecP256r1),
					string(configv1.TLSGroupSecP384r1),
				}, groupsPath...)
				return config, nil
			},
			expectedCurvePrefs: groupsToCurvePrefs(t, []configv1.TLSGroup{
				configv1.TLSGroupSecP256r1,
				configv1.TLSGroupSecP384r1,
			}),
			expectedMinVersion: string(configv1.VersionTLS12),
			expectedCipherSuites: []string{
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384",
			},
			expectError: true,
			expectedErrorStrings: func(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath []string) []string {
				return []string{
					"TLS groups filtered out from custom profile: [X25519 X25519MLKEM768]",
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: Implement proper FIPS-aware test expectations instead of skipping
			if crypto.IsFIPSEnabled() {
				t.Skip("FIPS mode enabled - test expectations need to be updated for FIPS-filtered groups")
			}

			for _, useAPIServerArgs := range []bool{false, true} {
				minTLSVersionPath := []string{"servingInfo", "minTLSVersion"}
				cipherSuitesPath := []string{"servingInfo", "cipherSuites"}
				curvePreferencesPath := []string{"servingInfo", "curvePreferences"}
				pathName := "FromServingInfo"
				if useAPIServerArgs {
					minTLSVersionPath = []string{"apiServerArguments", "tls-min-version"}
					cipherSuitesPath = []string{"apiServerArguments", "tls-cipher-suites"}
					curvePreferencesPath = []string{"apiServerArguments", "tls-curve-preferences"}
					pathName = "FromAPIServerArguments"
				}
				t.Run(pathName, func(t *testing.T) {
					listers, recorder := setupTLSGroupsTest(t, tt.apiServerTLSProfile)

					// Normalize existing config through JSON marshaling/unmarshaling to match real behavior.
					// In production, existingConfig comes from the CR's spec.observedConfig field, which is stored
					// in etcd as JSON. When retrieved, JSON numbers become float64 and concrete Go types like []string
					// become []interface{}. This round-trip simulates that normalization.
					var existingConfig map[string]interface{}
					if tt.existingConfig == nil {
						existingConfig = map[string]interface{}{}
					} else {
						existingConfig = tt.existingConfig(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath)
						jsonBytes, err := json.Marshal(existingConfig)
						if err != nil {
							t.Fatalf("failed to marshal existing config: %v", err)
						}
						if err := json.Unmarshal(jsonBytes, &existingConfig); err != nil {
							t.Fatalf("failed to unmarshal existing config: %v", err)
						}
					}

					var observedConfig map[string]interface{}
					var errs []error

					// Use mock if provided, otherwise use the real function
					if tt.mockObserveTLSSecurityProfile != nil {
						innerFunc := innerObserveTLSSecurityProfileWithGroupsConversion[int64]
						if useAPIServerArgs {
							innerFunc = innerObserveTLSSecurityProfileWithGroupsConversion[string]
						}

						observedConfig, errs = innerFunc(
							listers,
							recorder,
							existingConfig,
							tt.mockObserveTLSSecurityProfile,
							minTLSVersionPath,
							cipherSuitesPath,
							curvePreferencesPath,
						)
					} else {
						if useAPIServerArgs {
							observedConfig, errs = ObserveTLSSecurityProfileWithGroupsConversionToArguments(listers, recorder, existingConfig)
						} else {
							observedConfig, errs = ObserveTLSSecurityProfileWithGroupsConversion(listers, recorder, existingConfig)
						}
					}

					// Normalize observed config through JSON marshaling/unmarshaling to match real behavior.
					// In production, observedConfig is written to the CR's spec.observedConfig field and persisted
					// to etcd as JSON. When the operator reads it back (as existingConfig in the next reconcile),
					// the JSON round-trip converts int64 → float64 and other type normalizations. This simulates
					// that behavior so our expected values match what would actually be seen.
					if observedConfig != nil {
						jsonBytes, err := json.Marshal(observedConfig)
						if err != nil {
							t.Fatalf("failed to marshal observed config: %v", err)
						}
						if err := json.Unmarshal(jsonBytes, &observedConfig); err != nil {
							t.Fatalf("failed to unmarshal observed config: %v", err)
						}
					}

					if tt.expectError {
						if len(errs) == 0 {
							t.Fatal("expected errors, but got none")
						}
						if tt.expectedErrorStrings != nil {
							expectedErrors := tt.expectedErrorStrings(minTLSVersionPath, cipherSuitesPath, curvePreferencesPath)
							var actualErrorStrings []string
							for _, err := range errs {
								actualErrorStrings = append(actualErrorStrings, err.Error())
							}
							if !reflect.DeepEqual(actualErrorStrings, expectedErrors) {
								t.Errorf("error mismatch:\nexpected: %v\nactual:   %v", expectedErrors, actualErrorStrings)
							}
						}
					} else {
						if len(errs) > 0 {
							t.Fatalf("unexpected errors: %v", errs)
						}
					}

					if tt.expectedCurvePrefs != nil {
						// For apiServerArguments, curves are stored as strings, not int64
						if useAPIServerArgs {
							curvePrefsStrings, found, err := unstructured.NestedStringSlice(observedConfig, curvePreferencesPath...)
							if err != nil {
								t.Fatalf("failed to read curvePreferences: %v", err)
							}
							if !found {
								t.Error("curvePreferences should be set")
							} else {
								// Convert expected int64 values to strings for comparison
								expectedStrings := make([]string, len(tt.expectedCurvePrefs))
								for i, v := range tt.expectedCurvePrefs {
									expectedStrings[i] = fmt.Sprintf("%v", v)
								}
								if !reflect.DeepEqual(curvePrefsStrings, expectedStrings) {
									t.Errorf("curve preferences mismatch:\nexpected: %v\nactual:   %v",
										expectedStrings, curvePrefsStrings)
								}
							}
						} else {
							curvePrefs, found, err := unstructured.NestedSlice(observedConfig, curvePreferencesPath...)
							if err != nil {
								t.Fatalf("failed to read curvePreferences: %v", err)
							}
							if !found {
								t.Error("curvePreferences should be set")
							} else if !reflect.DeepEqual(curvePrefs, tt.expectedCurvePrefs) {
								t.Errorf("curve preferences mismatch:\nexpected: %v\nactual:   %v",
									tt.expectedCurvePrefs, curvePrefs)
							}
						}
					} else {
						_, found, _ := unstructured.NestedSlice(observedConfig, curvePreferencesPath...)
						if found {
							t.Error("curvePreferences should not be set when not expected")
						}
					}

					if tt.expectedMinVersion != "" {
						minVersion, found, err := unstructured.NestedString(observedConfig, minTLSVersionPath...)
						if err != nil {
							t.Fatalf("failed to read minTLSVersion: %v", err)
						}
						if !found {
							t.Error("minTLSVersion should be set")
						} else if minVersion != tt.expectedMinVersion {
							t.Errorf("expected minTLSVersion=%s, got: %v", tt.expectedMinVersion, minVersion)
						}
					} else {
						_, found, _ := unstructured.NestedString(observedConfig, minTLSVersionPath...)
						if found {
							t.Error("minTLSVersion should not be set when not expected")
						}
					}

					if tt.expectedCipherSuites != nil {
						cipherSuites, found, err := unstructured.NestedStringSlice(observedConfig, cipherSuitesPath...)
						if err != nil {
							t.Fatalf("failed to read cipherSuites: %v", err)
						}
						if !found {
							t.Error("cipherSuites should be set")
						} else if !reflect.DeepEqual(cipherSuites, tt.expectedCipherSuites) {
							t.Errorf("cipher suites mismatch:\nexpected: %v\nactual:   %v",
								tt.expectedCipherSuites, cipherSuites)
						}
					} else {
						_, found, _ := unstructured.NestedStringSlice(observedConfig, cipherSuitesPath...)
						if found {
							t.Error("cipherSuites should not be set when not expected")
						}
					}

					if tempField, found, err := unstructured.NestedFieldNoCopy(observedConfig, tempTLSGroupsField); err != nil {
						t.Errorf("error checking temp field %s: %v", tempTLSGroupsField, err)
					} else if found {
						t.Errorf("temp field %s should be removed from observedConfig, got: %v", tempTLSGroupsField, tempField)
					}

					for _, event := range recorder.Events() {
						if event.Reason == "ObservationFailed" {
							t.Errorf("unexpected observation failure: %s", event.Message)
						}
					}
				})
			}
		})
	}
}
