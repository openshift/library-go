package cloudprovider

import (
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/cloudprovider"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
)

// NewCloudVolumePluginObserver returns a new cloudprovider observer for syncing cloud provider specific
// information to controller-manager, leaving only storage controller loops enabled.
func NewCloudVolumePluginObserver(targetNamespaceName string, cloudVolumePluginPath, cloudProviderConfigPath []string) configobserver.ObserveConfigFunc {
	cloudObserver := &cloudProviderObserver{
		targetNamespaceName:     targetNamespaceName,
		cloudProviderNamePath:   cloudVolumePluginPath,
		cloudProviderConfigPath: cloudProviderConfigPath,
	}
	return cloudObserver.ObserveCloudVolumePlugin
}

// ObserveCloudVolumePlugin fills in the cluster-name extended argument for the controller-manager with the cluster's infra ID
func (c *cloudProviderObserver) ObserveCloudVolumePlugin(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, errs []error) {
	defer func() {
		ret = configobserver.Pruned(ret, c.cloudProviderConfigPath, c.cloudProviderNamePath)
	}()

	listers := genericListers.(InfrastructureLister)
	volumePluginPath := c.cloudProviderNamePath
	previouslyObservedConfig := map[string]interface{}{}

	if currentVolumePlugin, _, _ := unstructured.NestedStringSlice(existingConfig, volumePluginPath...); len(currentVolumePlugin) > 0 {
		if err := unstructured.SetNestedStringSlice(previouslyObservedConfig, currentVolumePlugin, volumePluginPath...); err != nil {
			errs = append(errs, err)
		}
	}

	infrastructure, err := listers.InfrastructureLister().Get("cluster")
	if err != nil {
		if errors.IsNotFound(err) {
			recorder.Warningf("ObserveCloudVolumePlugin", "Required infrastructures.%s/cluster not found", configv1.GroupName)
		}
		return previouslyObservedConfig, errs
	}

	featureGate, err := listers.FeatureGateLister().Get("cluster")
	if errors.IsNotFound(err) {
		recorder.Eventf("ObserveCloudVolumePlugin", "Optional featuregate.%s/cluster not found", configv1.GroupName)
	} else if err != nil {
		return previouslyObservedConfig, append(errs, err)
	}

	external, err := cloudprovider.IsCloudProviderExternal(infrastructure.Status.Platform, featureGate)
	if err != nil {
		recorder.Eventf("ObserveCloudVolumePlugin", "Invalid featuregate.%s/cluster format: %v", err)
	} else if !external {
		// Running in-tree volumes - no configuration needed. Skip
		return previouslyObservedConfig, errs
	}

	observedConfig := map[string]interface{}{}

	// Set --external-cloud-volume-plugin=<cloudProvider> for external
	cloudProvider := getPlatformName(infrastructure.Status.Platform, recorder)
	if len(cloudProvider) > 0 {
		if err := unstructured.SetNestedStringSlice(observedConfig, []string{cloudProvider}, volumePluginPath...); err != nil {
			errs = append(errs, err)
		}
	}

	// Set cloudProviderConfig value
	existingCloudConfig, _, err := unstructured.NestedStringSlice(existingConfig, c.cloudProviderConfigPath...)
	if err != nil {
		errs = append(errs, err)
		// keep going on read error from existing config
	}

	cloudProviderConfig, configErrs := c.getCloudProviderConfig(genericListers, recorder, infrastructure)
	if configErrs != nil {
		errs = append(errs, configErrs...)
	}

	if err := unstructured.SetNestedStringSlice(observedConfig, []string{cloudProviderConfig}, c.cloudProviderConfigPath...); err != nil {
		recorder.Warningf("ObserveCloudProviderNames", "Failed setting cloud-config : %v", err)
		return nil, append(errs, err)
	}

	if !equality.Semantic.DeepEqual(existingCloudConfig, []string{cloudProviderConfig}) {
		recorder.Eventf("ObserveCloudProviderNamesChanges", "CloudProvider config file changed to %s", cloudProviderConfig)
	}

	return observedConfig, errs
}
