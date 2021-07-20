package cloudprovider

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	corelisterv1 "k8s.io/client-go/listers/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

const (
	configNamespace                 = "openshift-config"
	machineSpecifiedConfigNamespace = "openshift-config-managed"
	machineSpecifiedConfig          = "kube-cloud-config"
)

var cloudProviders = sets.NewString("azure", "gce", "openstack", "vsphere")

// InfrastructureLister lists infrastructure information and allows resources to be synced
type InfrastructureLister interface {
	InfrastructureLister() configlistersv1.InfrastructureLister
	ResourceSyncer() resourcesynccontroller.ResourceSyncer
	ConfigMapLister() corelisterv1.ConfigMapLister
}

// NewCloudConfigSyncer returns a new cloudprovider dependent observer for syncing cloud config per provider
// for controller-manager and api-server.
func NewCloudConfigSyncer(targetNamespaceName string) configobserver.ObserveConfigFunc {
	cloudObserver := &cloudConfigSyncer{
		targetNamespaceName: targetNamespaceName,
	}
	return cloudObserver.SyncCloudConfig
}

type cloudConfigSyncer struct {
	targetNamespaceName string
}

// SyncCloudConfig syncs cloud config from the global cluster infrastructure resource
// or from openshift-config namespace on each config observation request
func (c *cloudConfigSyncer) SyncCloudConfig(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	listers := genericListers.(InfrastructureLister)

	infrastructure, err := listers.InfrastructureLister().Get("cluster")
	if err != nil {
		return nil, []error{err}
	}

	cloudProvider, err := getPlatformName(infrastructure.Status.Platform, recorder)
	if err != nil {
		return nil, []error{err}
	}

	// we copy cloudprovider configmap values only for some cloud providers.
	if !cloudProviders.Has(cloudProvider) {
		return nil, nil
	}

	sourceCloudConfigMap := infrastructure.Spec.CloudConfig.Name
	sourceCloudConfigNamespace := configNamespace

	// If a managed cloud-provider config is available, it should be used instead of the default. If the configmap is not
	// found, the default values should be used.
	if _, err = listers.ConfigMapLister().ConfigMaps(machineSpecifiedConfigNamespace).Get(machineSpecifiedConfig); err == nil {
		sourceCloudConfigMap = machineSpecifiedConfig
		sourceCloudConfigNamespace = machineSpecifiedConfigNamespace
	} else if !errors.IsNotFound(err) {
		return nil, []error{err}
	}

	sourceLocation := resourcesynccontroller.ResourceLocation{
		Namespace: sourceCloudConfigNamespace,
		Name:      sourceCloudConfigMap,
		Provider:  cloudProvider,
	}

	if err := listers.ResourceSyncer().SyncConfigMap(
		resourcesynccontroller.ResourceLocation{
			Namespace: c.targetNamespaceName,
			Name:      "cloud-config",
			Provider:  cloudProvider,
		},
		sourceLocation); err != nil {
		return nil, []error{err}
	}

	return nil, nil
}

func getPlatformName(platformType configv1.PlatformType, recorder events.Recorder) (string, error) {
	cloudProvider := ""
	var err error
	switch platformType {
	case "":
		err = fmt.Errorf("required status.platform field is not set in infrastructures.%s/cluster", configv1.GroupName)
	case configv1.AWSPlatformType:
		cloudProvider = "aws"
	case configv1.AzurePlatformType:
		cloudProvider = "azure"
	case configv1.VSpherePlatformType:
		cloudProvider = "vsphere"
	case configv1.BareMetalPlatformType:
	case configv1.GCPPlatformType:
		cloudProvider = "gce"
	case configv1.LibvirtPlatformType:
	case configv1.OpenStackPlatformType:
		cloudProvider = "openstack"
	case configv1.NonePlatformType:
	case configv1.OvirtPlatformType:
	case configv1.KubevirtPlatformType:
	default:
		// the new doc on the infrastructure fields requires that we treat an unrecognized thing the same bare metal.
		// TODO find a way to indicate to the user that we didn't honor their choice
		err = fmt.Errorf("no recognized cloud provider platform found in infrastructures.%s/cluster.status.platform", configv1.GroupName)
	}
	return cloudProvider, err
}
