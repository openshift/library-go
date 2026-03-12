package featuregates

import (
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

type testLister struct {
	lister configlistersv1.FeatureGateLister
}

func (l testLister) FeatureGateLister() configlistersv1.FeatureGateLister {
	return l.lister
}

func (l testLister) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return nil
}

func (l testLister) PreRunHasSynced() []cache.InformerSynced {
	return nil
}

func TestObserveFeatureFlags(t *testing.T) {
	configPath := []string{"foo", "bar"}

	tests := []struct {
		name                                  string
		accessor                              FeatureGateAccess
		expectedResult                        []string
		expectError                           bool
		knownFeatures                         sets.Set[configv1.FeatureGateName]
		blacklistedFeatures                   sets.Set[configv1.FeatureGateName]
		blackListedFeaturesExplicitlyDisabled sets.Set[configv1.FeatureGateName]
	}{
		{
			name: "default",
			accessor: NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{"OpenShiftPodSecurityAdmission"},
				[]configv1.FeatureGateName{"RetroactiveDefaultStorageClass"},
			),
			expectedResult: []string{
				"OpenShiftPodSecurityAdmission=true",
				"RetroactiveDefaultStorageClass=false",
			},
		},
		{
			name: "techpreview",
			accessor: NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{
					"OpenShiftPodSecurityAdmission",
					"ExternalCloudProvider",
					"CSIDriverSharedResource",
					"BuildCSIVolumes",
					"NodeSwap",
					"MachineAPIProviderOpenStack",
					"InsightsConfigAPI",
					"MatchLabelKeysInPodTopologySpread",
					"PDBUnhealthyPodEvictionPolicy",
				},
				[]configv1.FeatureGateName{
					"RetroactiveDefaultStorageClass",
				},
			),
			expectedResult: []string{
				"BuildCSIVolumes=true",
				"CSIDriverSharedResource=true",
				"ExternalCloudProvider=true",
				"InsightsConfigAPI=true",
				"MachineAPIProviderOpenStack=true",
				"MatchLabelKeysInPodTopologySpread=true",
				"NodeSwap=true",
				"OpenShiftPodSecurityAdmission=true",
				"PDBUnhealthyPodEvictionPolicy=true",
				"RetroactiveDefaultStorageClass=false",
			},
		},
		{
			name: "custom no upgrade and all allowed",
			accessor: NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{"CustomFeatureEnabled"},
				[]configv1.FeatureGateName{"CustomFeatureDisabled"},
			),
			expectedResult: []string{
				"CustomFeatureDisabled=false",
				"CustomFeatureEnabled=true",
			},
		},
		{
			name:           "custom no upgrade flag set and none upgrades were provided",
			accessor:       NewHardcodedFeatureGateAccess(nil, nil),
			expectedResult: []string{},
		},
		{
			name: "custom no upgrade and known features",
			accessor: NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{"CustomFeatureEnabled"},
				[]configv1.FeatureGateName{"CustomFeatureDisabled"},
			),
			expectedResult: []string{
				"CustomFeatureEnabled=true",
			},
			knownFeatures: sets.New[configv1.FeatureGateName]("CustomFeatureEnabled"),
		},
		{
			name: "custom no upgrade and blacklisted features",
			accessor: NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{"CustomFeatureEnabled", "AnotherThing", "AThirdThing"},
				[]configv1.FeatureGateName{"CustomFeatureDisabled", "DisabledThing"},
			),
			expectedResult: []string{
				"AThirdThing=true",
				"CustomFeatureDisabled=false",
				"CustomFeatureEnabled=true",
			},
			blacklistedFeatures: sets.New[configv1.FeatureGateName]("AnotherThing", "DisabledThing"),
		},
		{
			name: "explicitly disabled features in known features",
			accessor: NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{"FeatureA", "FeatureB", "FeatureC"},
				[]configv1.FeatureGateName{"FeatureD"},
			),
			expectedResult: []string{
				"FeatureA=true",
				"FeatureB=false",
				"FeatureC=true",
				"FeatureD=false",
			},
			blackListedFeaturesExplicitlyDisabled: sets.New[configv1.FeatureGateName]("FeatureB"),
		},
		{
			name: "explicitly disabled features not in known features",
			accessor: NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{"FeatureA", "FeatureB"},
				[]configv1.FeatureGateName{},
			),
			expectedResult: []string{
				"FeatureA=true",
				"FeatureB=true",
				"UnknownFeature=false",
			},
			blackListedFeaturesExplicitlyDisabled: sets.New[configv1.FeatureGateName]("UnknownFeature"),
		},
		{
			name: "combination of blacklist and explicit disablement",
			accessor: NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{"Feature1", "Feature2", "Feature3", "Feature4"},
				[]configv1.FeatureGateName{"Feature5"},
			),
			expectedResult: []string{
				"Feature1=true",
				"Feature3=false",
				"Feature4=true",
				"Feature5=false",
			},
			blacklistedFeatures:                   sets.New[configv1.FeatureGateName]("Feature2"),
			blackListedFeaturesExplicitlyDisabled: sets.New[configv1.FeatureGateName]("Feature3"),
		},
		{
			name: "explicit disablement with unknown features",
			accessor: NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{"EnabledFeature1", "EnabledFeature2"},
				[]configv1.FeatureGateName{"DisabledFeature"},
			),
			expectedResult: []string{
				"DisabledFeature=false",
				"EnabledFeature1=true",
				"EnabledFeature2=false",
				"NotInKnownList=false",
			},
			blackListedFeaturesExplicitlyDisabled: sets.New[configv1.FeatureGateName]("EnabledFeature2", "NotInKnownList"),
		},
		{
			name: "initial gates not observed",
			accessor: NewHardcodedFeatureGateAccessForTesting(
				[]configv1.FeatureGateName{"CustomFeatureEnabled"},
				[]configv1.FeatureGateName{"CustomFeatureDisabled"},
				make(chan struct{}),
				nil,
			),
			expectedResult: nil,
		},
		{
			name: "error getting current gates",
			accessor: NewHardcodedFeatureGateAccessForTesting(
				[]configv1.FeatureGateName{"CustomFeatureEnabled"},
				[]configv1.FeatureGateName{"CustomFeatureDisabled"},
				func() chan struct{} {
					c := make(chan struct{})
					close(c)
					return c
				}(),
				errors.New("test error"),
			),
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eventRecorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
			initialExistingConfig := map[string]interface{}{}
			observeFn := NewObserveFeatureFlagsFunc(tc.knownFeatures, tc.blacklistedFeatures, tc.blackListedFeaturesExplicitlyDisabled, configPath, tc.accessor)

			observed, errs := observeFn(nil, eventRecorder, initialExistingConfig)
			if len(errs) != 0 && !tc.expectError {
				t.Fatal(errs)
			}
			if len(errs) == 0 && tc.expectError {
				t.Fatal("expected an error but got nothing")
			}
			actual, _, err := unstructured.NestedStringSlice(observed, configPath...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Sort the result for comparison with the expected result
			slices.Sort(actual)
			if !reflect.DeepEqual(tc.expectedResult, actual) {
				t.Errorf("Unexpected features gates\n  got:      %v\n  expected: %v", actual, tc.expectedResult)
			}
		})
	}
}
