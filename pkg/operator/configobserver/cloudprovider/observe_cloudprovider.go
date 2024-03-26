package cloudprovider

import (
	corelisterv1 "k8s.io/client-go/listers/core/v1"

	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

const (
	cloudProviderConfFilePath       = "/etc/kubernetes/static-pod-resources/configmaps/cloud-config/%s"
	configNamespace                 = "openshift-config"
	machineSpecifiedConfigNamespace = "openshift-config-managed"
	machineSpecifiedConfig          = "kube-cloud-config"
)

// InfrastructureLister lists infrastrucre information and allows resources to be synced
type InfrastructureLister interface {
	InfrastructureLister() configlistersv1.InfrastructureLister
	ResourceSyncer() resourcesynccontroller.ResourceSyncer
	ConfigMapLister() corelisterv1.ConfigMapLister
}

// NewCloudProviderObserver returns a new cloudprovider observer for syncing cloud provider specific
// information to controller-manager and api-server.
func NewCloudProviderObserver(targetNamespaceName string, skipCloudProviderExternal bool) configobserver.ObserveConfigFunc {
	cloudObserver := &cloudProviderObserver{
		targetNamespaceName:       targetNamespaceName,
		skipCloudProviderExternal: skipCloudProviderExternal,
	}
	return cloudObserver.ObserveCloudProviderNames
}

type cloudProviderObserver struct {
	targetNamespaceName       string
	skipCloudProviderExternal bool
}

// ObserveCloudProviderNames observes the cloud provider from the global cluster infrastructure resource.
func (c *cloudProviderObserver) ObserveCloudProviderNames(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	defer func() {
		ret = configobserver.Pruned(ret)
	}()

	listers := genericListers.(InfrastructureLister)
	var errs []error

	// Use a blank resource location to delete the old, unused cloud-config configmap, if it exists.
	_ = listers.ResourceSyncer().SyncConfigMap(
		resourcesynccontroller.ResourceLocation{
			Namespace: c.targetNamespaceName,
			Name:      "cloud-config",
		},
		resourcesynccontroller.ResourceLocation{})

	return existingConfig, errs
}
