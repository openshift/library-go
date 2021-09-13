package featuregate

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
)

func TestGetEnabledAndDisabledFeatures(t *testing.T) {
	tests := []struct {
		name             string
		configValue      configv1.FeatureSet
		customNoUpgrade  *configv1.CustomFeatureGates
		expectError      bool
		expectedEnabled  []string
		expectedDisabled []string
	}{
		{
			name:             "default",
			expectedEnabled:  configv1.FeatureSets[configv1.Default].Enabled,
			expectedDisabled: configv1.FeatureSets[configv1.Default].Disabled,
		},
		{
			name:             "techpreview",
			configValue:      configv1.TechPreviewNoUpgrade,
			expectedEnabled:  configv1.FeatureSets[configv1.TechPreviewNoUpgrade].Enabled,
			expectedDisabled: configv1.FeatureSets[configv1.TechPreviewNoUpgrade].Disabled,
		},
		{
			name:        "custom no upgrade",
			configValue: configv1.CustomNoUpgrade,
			customNoUpgrade: &configv1.CustomFeatureGates{
				Enabled:  []string{"CustomEnabledFeature"},
				Disabled: []string{"CustomDisabledFeature"},
			},
			expectedEnabled:  []string{"CustomEnabledFeature"},
			expectedDisabled: []string{"CustomDisabledFeature"},
		},
		{
			name:        "unknown",
			configValue: configv1.FeatureSet("UnknownDoesntExist"),
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fg := &configv1.FeatureGate{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.FeatureGateSpec{
					FeatureGateSelection: configv1.FeatureGateSelection{
						FeatureSet:      tc.configValue,
						CustomNoUpgrade: tc.customNoUpgrade,
					},
				},
			}
			enabled, disabled, err := GetEnabledAndDisabledFeatures(fg)
			if err != nil && !tc.expectError {
				t.Fatalf("unexpected error occurred: %v", err)
			}
			if err == nil && tc.expectError {
				t.Fatal("expected error to occur but got nothing")
			}
			if !equality.Semantic.DeepEqual(enabled, tc.expectedEnabled) {
				t.Errorf("expected enabled list of features\n  %s,\ngot\n  %s", tc.expectedEnabled, enabled)
			}
			if !equality.Semantic.DeepEqual(disabled, tc.expectedDisabled) {
				t.Errorf("expected disabled list of features\n  %s,\ngot\n  %s", tc.expectedDisabled, disabled)
			}
		})
	}
}

func TestIsFeatureEnabled(t *testing.T) {
	tests := []struct {
		name            string
		configValue     configv1.FeatureSet
		customNoUpgrade *configv1.CustomFeatureGates
		testFeature     string
		expectedResult  bool
		expectError     bool
	}{
		{
			name: "default - enabled",
			// Note - GA flag is assumed to always be present in the default feature set.
			testFeature:    "APIPriorityAndFairness",
			expectedResult: true,
		},
		{
			name: "default - disabled",
			// Note - disabled GA flag is assumed to always be present in the default feature set.
			testFeature:    "LegacyNodeRoleBehavior",
			expectedResult: false,
		},
		{
			name:           "default - not on list",
			testFeature:    "UnknownFeatureGate",
			expectedResult: false,
		},
		{
			name: "techpreview",
			// Note - tech preview is assumed to be a superset of default features.
			// Therefore the test feature here may graduate to the default feature set over time.
			testFeature:    "CSIDriverAzureDisk",
			configValue:    configv1.TechPreviewNoUpgrade,
			expectedResult: true,
		},
		{
			name:        "custom - enabled",
			testFeature: "CustomEnabledFeature",
			configValue: configv1.CustomNoUpgrade,
			customNoUpgrade: &configv1.CustomFeatureGates{
				Enabled:  []string{"CustomEnabledFeature"},
				Disabled: []string{"CustomDisabledFeature"},
			},
			expectedResult: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fg := &configv1.FeatureGate{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.FeatureGateSpec{
					FeatureGateSelection: configv1.FeatureGateSelection{
						FeatureSet:      tc.configValue,
						CustomNoUpgrade: tc.customNoUpgrade,
					},
				},
			}
			result, err := IsFeatureGateEnabled(tc.testFeature, fg)
			if err != nil && !tc.expectError {
				t.Fatalf("unexpected error occurred: %v", err)
			}
			if err == nil && tc.expectError {
				t.Fatal("expected error but got nothing")
			}
			if result != tc.expectedResult {
				t.Errorf("expected feature %s to be enabled=%t, got %t", tc.testFeature, tc.expectedResult, result)
			}
		})
	}
}
