package featuregates

import (
	"reflect"
	"testing"

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

var testingFeatureSets = map[configv1.FeatureSet]configv1.FeatureGateEnabledDisabled{
	configv1.Default: {
		Enabled: []string{
			"OpenShiftPodSecurityAdmission", // bz-auth, stlaz, OCP specific
		},
		Disabled: []string{
			"RetroactiveDefaultStorageClass", // sig-storage, RomanBednar, Kubernetes feature gate
		},
	},
	configv1.CustomNoUpgrade: {
		Enabled:  []string{},
		Disabled: []string{},
	},
	configv1.TechPreviewNoUpgrade: {
		Enabled: []string{
			"OpenShiftPodSecurityAdmission",     // bz-auth, stlaz, OCP specific
			"ExternalCloudProvider",             // sig-cloud-provider, jspeed, OCP specific
			"CSIDriverSharedResource",           // sig-build, adkaplan, OCP specific
			"BuildCSIVolumes",                   // sig-build, adkaplan, OCP specific
			"NodeSwap",                          // sig-node, ehashman, Kubernetes feature gate
			"MachineAPIProviderOpenStack",       // openstack, egarcia (#forum-openstack), OCP specific
			"InsightsConfigAPI",                 // insights, tremes (#ccx), OCP specific
			"MatchLabelKeysInPodTopologySpread", // sig-scheduling, ingvagabund (#forum-workloads), Kubernetes feature gate
			"PDBUnhealthyPodEvictionPolicy",     // sig-apps, atiratree (#forum-workloads), Kubernetes feature gate
		},
		Disabled: []string{
			"RetroactiveDefaultStorageClass", // sig-storage, RomanBednar, Kubernetes feature gate
		},
	},
}

func TestObserveFeatureFlags(t *testing.T) {
	configPath := []string{"foo", "bar"}

	tests := []struct {
		name string

		configValue         configv1.FeatureSet
		expectedResult      []string
		expectError         bool
		customNoUpgrade     *configv1.CustomFeatureGates
		knownFeatures       sets.Set[configv1.FeatureGateName]
		blacklistedFeatures sets.Set[configv1.FeatureGateName]
	}{
		{
			name:        "default",
			configValue: configv1.Default,
			expectedResult: []string{
				"OpenShiftPodSecurityAdmission=true",
				"RetroactiveDefaultStorageClass=false",
			},
		},
		{
			name:        "techpreview",
			configValue: configv1.TechPreviewNoUpgrade,
			expectedResult: []string{
				"OpenShiftPodSecurityAdmission=true",
				"ExternalCloudProvider=true",
				"CSIDriverSharedResource=true",
				"BuildCSIVolumes=true",
				"NodeSwap=true",
				"MachineAPIProviderOpenStack=true",
				"InsightsConfigAPI=true",
				"MatchLabelKeysInPodTopologySpread=true",
				"PDBUnhealthyPodEvictionPolicy=true",
				"RetroactiveDefaultStorageClass=false",
			},
		},
		{
			name:        "custom no upgrade and all allowed",
			configValue: configv1.CustomNoUpgrade,
			expectedResult: []string{
				"CustomFeatureEnabled=true",
				"CustomFeatureDisabled=false",
			},
			customNoUpgrade: &configv1.CustomFeatureGates{
				Enabled:  []configv1.FeatureGateName{"CustomFeatureEnabled"},
				Disabled: []configv1.FeatureGateName{"CustomFeatureDisabled"},
			},
		},
		{
			name:           "custom no upgrade flag set and none upgrades were provided",
			configValue:    configv1.CustomNoUpgrade,
			expectedResult: []string{},
		},
		{
			name:        "custom no upgrade and known features",
			configValue: configv1.CustomNoUpgrade,
			expectedResult: []string{
				"CustomFeatureEnabled=true",
			},
			customNoUpgrade: &configv1.CustomFeatureGates{
				Enabled:  []configv1.FeatureGateName{"CustomFeatureEnabled"},
				Disabled: []configv1.FeatureGateName{"CustomFeatureDisabled"},
			},
			knownFeatures: sets.New[configv1.FeatureGateName]("CustomFeatureEnabled"),
		},
		{
			name:        "custom no upgrade and blacklisted features",
			configValue: configv1.CustomNoUpgrade,
			expectedResult: []string{
				"CustomFeatureEnabled=true",
				"AThirdThing=true",
				"CustomFeatureDisabled=false",
			},
			customNoUpgrade: &configv1.CustomFeatureGates{
				Enabled:  []configv1.FeatureGateName{"CustomFeatureEnabled", "AnotherThing", "AThirdThing"},
				Disabled: []configv1.FeatureGateName{"CustomFeatureDisabled", "DisabledThing"},
			},
			blacklistedFeatures: sets.New[configv1.FeatureGateName]("AnotherThing", "DisabledThing"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apiEnabledDisabled := testingFeatureSets[tc.configValue]
			enabled := []configv1.FeatureGateName{}
			enabled = append(enabled, StringsToFeatureGateNames(apiEnabledDisabled.Enabled)...)
			disabled := []configv1.FeatureGateName{}
			disabled = append(disabled, StringsToFeatureGateNames(apiEnabledDisabled.Disabled)...)

			if tc.customNoUpgrade != nil {
				enabled = append(enabled, tc.customNoUpgrade.Enabled...)
				disabled = append(disabled, tc.customNoUpgrade.Disabled...)
			}
			featureAccessor := NewHardcodedFeatureGateAccess(enabled, disabled)
			eventRecorder := events.NewInMemoryRecorder("")
			initialExistingConfig := map[string]interface{}{}
			observeFn := NewObserveFeatureFlagsFunc(tc.knownFeatures, tc.blacklistedFeatures, configPath, featureAccessor)

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
			if !reflect.DeepEqual(tc.expectedResult, actual) {
				t.Errorf("Unexpected features gates\n  got:      %v\n  expected: %v", actual, tc.expectedResult)
			}
		})
	}
}
