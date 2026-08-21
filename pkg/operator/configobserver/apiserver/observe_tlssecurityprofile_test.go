package apiserver

import (
	"reflect"
	"strings"
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
	// The observer FIPS-filters groups, so expectations differ by runtime mode.
	// Under fips140=on, X25519MLKEM768 and X25519 are dropped; only the NIST
	// P-curves survive.
	fips := isFIPSEnabled()
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
