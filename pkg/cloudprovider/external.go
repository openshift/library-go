package cloudprovider

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	// ExternalCloudProviderFeature is the name of the external cloud provider feature gate.
	// This is used to flag to operators that the cluster should be using the external cloud-controller-manager
	// rather than the in-tree cloud controller loops.
	ExternalCloudProviderFeature = "ExternalCloudProvider"
)

// IsCloudProviderExternal is used to check whether external cloud provider settings should be used in a component.
// It checks whether the ExternalCloudProvider feature gate is enabled and whether the ExternalCloudProvider feature
// has been implemented for the platform.
func IsCloudProviderExternal(platformStatus *configv1.PlatformStatus, featureGate *configv1.FeatureGate) (bool, error) {
	if platformStatus == nil {
		return false, fmt.Errorf("platformStatus is required")
	}
	switch platformStatus.Type {
	case configv1.VSpherePlatformType:
		// vSphere has a special condition whereby CCM reversion must be possible in 4.13 OpenShift if the in-tree storage driver is enabled
		disabled, err := isCSIMigrationvSphereDisabled(featureGate)
		// we only want to use the in-tree cloud-provider when the migration is also disabled
		return !disabled, err
	case configv1.GCPPlatformType:
		// Platforms that are external based on feature gate presence
		return isExternalFeatureGateEnabled(featureGate)
	case configv1.AlibabaCloudPlatformType,
		configv1.AWSPlatformType,
		configv1.AzurePlatformType,
		configv1.IBMCloudPlatformType,
		configv1.KubevirtPlatformType,
		configv1.NutanixPlatformType,
		configv1.OpenStackPlatformType,
		configv1.PowerVSPlatformType:
		return true, nil
	default:
		// Platforms that do not have external cloud providers implemented
		return false, nil
	}
}

// isExternalFeatureGateEnabled determines whether the ExternalCloudProvider feature gate is present in the current
// feature set.
func isExternalFeatureGateEnabled(featureGate *configv1.FeatureGate) (bool, error) {
	if featureGate == nil {
		// If no featureGate is present, then the user hasn't opted in to the external cloud controllers
		return false, nil
	}

	enabledFeatureGates, disabledFeatureGates, err := getEnabledDisabledFeatureGates(featureGate)
	if err != nil {
		return false, err
	}

	return !disabledFeatureGates.Has(ExternalCloudProviderFeature) && enabledFeatureGates.Has(ExternalCloudProviderFeature), nil
}

// isCSIMigrationvSphereDisabled determines whether the CSIMigrationvSphere feature gate is disabled in the current
// feature set. This function only returns true when the feature is actively disabled, otherwise we should
// deploy the CCM for vSphere.
// This function is needed to help address a reversion issue that is happening in 1.26 Kubernetes,
// which is also being brought to 4.13 OpenShift. This feature gate had been locked for 1.26, but has been
// unlocked in https://github.com/kubernetes/kubernetes/pull/116342. This feature gate had been removed from OpenShift
// as all vSphere clusters will be migrated to the CSI driver, due to the reversion we must support a situation where
// a user has upgraded to 4.13 but must revert their storage driver to in-tree. This reversion will also require the
// CCM to be migrated back to the in-tree KCM. Related storage JIRA, https://issues.redhat.com/browse/STOR-1265
// TODO remove this function once it is no longer needed, presumably 4.14 OpenShift.
func isCSIMigrationvSphereDisabled(featureGate *configv1.FeatureGate) (bool, error) {
	if featureGate == nil {
		// If no featureGate is present, then the user hasn't opted in to the in-tree vSphere driver
		return false, nil
	}

	enabledFeatureGates, disabledFeatureGates, err := getEnabledDisabledFeatureGates(featureGate)
	if err != nil {
		return false, err
	}

	return !disabledFeatureGates.Has(configv1.InTreeVSphereVolumes) && enabledFeatureGates.Has(configv1.InTreeVSphereVolumes), nil
}

// get the enabled and disabled feature gates for the associated feature set
func getEnabledDisabledFeatureGates(featureGate *configv1.FeatureGate) (sets.String, sets.String, error) {
	featureSet, ok := configv1.FeatureSets[featureGate.Spec.FeatureSet]
	if !ok {
		return nil, nil, fmt.Errorf(".spec.featureSet %q not found", featureGate.Spec.FeatureSet)
	}

	enabled := sets.NewString(featureSet.Enabled...)
	disabled := sets.NewString(featureSet.Disabled...)
	// CustomNoUpgrade will override the default enabled feature gates.
	if featureGate.Spec.FeatureSet == configv1.CustomNoUpgrade && featureGate.Spec.CustomNoUpgrade != nil {
		enabled = sets.NewString(featureGate.Spec.CustomNoUpgrade.Enabled...)
		disabled = sets.NewString(featureGate.Spec.CustomNoUpgrade.Disabled...)
	}

	return enabled, disabled, nil
}
