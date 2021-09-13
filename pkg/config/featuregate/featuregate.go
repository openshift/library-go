package featuregate

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
)

// GetEnabledAndDisabledFeatures returns a list of enabled and disabled features for the given `FeatureGate` instance.
// Returns an error if the object references an unknown feature set.
func GetEnabledAndDisabledFeatures(fg *configv1.FeatureGate) ([]string, []string, error) {
	if fg.Spec.FeatureSet == configv1.CustomNoUpgrade {
		if fg.Spec.FeatureGateSelection.CustomNoUpgrade != nil {
			return fg.Spec.FeatureGateSelection.CustomNoUpgrade.Enabled, fg.Spec.FeatureGateSelection.CustomNoUpgrade.Disabled, nil
		}
		return []string{}, []string{}, nil
	}

	featureSet, ok := configv1.FeatureSets[fg.Spec.FeatureSet]
	if !ok {
		return []string{}, []string{}, fmt.Errorf("featureSet %q is not a known set of features", featureSet)
	}
	return featureSet.Enabled, featureSet.Disabled, nil
}

// IsFeatureGateEnabled returns true if the provided feature is explicitly enabled by the given `FeatureGate` instance.
// This returns false if the feature is explicitly disabled or is not enabled by the referenced feature set.
// Returns an error if the `FeatureGate` references an unknown feature set.
func IsFeatureGateEnabled(feature string, fg *configv1.FeatureGate) (bool, error) {
	enabledFeatures, disabledFeatures, err := GetEnabledAndDisabledFeatures(fg)
	if err != nil {
		return false, err
	}
	for _, disabledFeature := range disabledFeatures {
		if feature == disabledFeature {
			return false, nil
		}
	}
	for _, enabledFeature := range enabledFeatures {
		if feature == enabledFeature {
			return true, nil
		}
	}
	return false, nil
}
