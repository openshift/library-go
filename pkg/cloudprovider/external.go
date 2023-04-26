package cloudprovider

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	configv1 "github.com/openshift/api/config/v1"
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
func IsCloudProviderExternal(platformStatus *configv1.PlatformStatus, featureGateAccessor featuregates.FeatureGateAccess) (bool, error) {
	if !featureGateAccessor.AreInitialFeatureGatesObserved() {
		return false, fmt.Errorf("featureGates have not been read yet")
	}
	if platformStatus == nil {
		return false, fmt.Errorf("platformStatus is required")
	}
	switch platformStatus.Type {
	case configv1.GCPPlatformType:
		// Platforms that are external based on feature gate presence
		return isExternalFeatureGateEnabled(featureGateAccessor)
	case configv1.AzurePlatformType:
		if isAzureStackHub(platformStatus) {
			return true, nil
		}
		return isExternalFeatureGateEnabled(featureGateAccessor)
	case configv1.AlibabaCloudPlatformType,
		configv1.AWSPlatformType,
		configv1.IBMCloudPlatformType,
		configv1.KubevirtPlatformType,
		configv1.NutanixPlatformType,
		configv1.OpenStackPlatformType,
		configv1.PowerVSPlatformType,
		configv1.VSpherePlatformType:
		return true, nil
	default:
		// Platforms that do not have external cloud providers implemented
		return false, nil
	}
}

func isAzureStackHub(platformStatus *configv1.PlatformStatus) bool {
	return platformStatus.Azure != nil && platformStatus.Azure.CloudName == configv1.AzureStackCloud
}

// isExternalFeatureGateEnabled determines whether the ExternalCloudProvider feature gate is present in the current
// feature set.
func isExternalFeatureGateEnabled(featureGateAccess featuregates.FeatureGateAccess) (bool, error) {
	enabled, disabled, err := featureGateAccess.CurrentFeatureGates()
	if err != nil {
		return false, fmt.Errorf("unable to read current featuregates: %w", err)
	}

	enabledFeatureGates := sets.New[configv1.FeatureGateName](enabled...)
	disabledFeatureGates := sets.New[configv1.FeatureGateName](disabled...)

	// TODO left to be compatible, but we should standardize on positive checks only.
	return !disabledFeatureGates.Has(configv1.FeatureGateExternalCloudProvider) && enabledFeatureGates.Has(configv1.FeatureGateExternalCloudProvider), nil
}
