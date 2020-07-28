package masterurl

import (
	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// InfrastructureLister lists infrastructure information and allows resources to be synced
type InfrastructureLister interface {
	InfrastructureLister() configlistersv1.InfrastructureLister
}

// ObserveMasterURL fills in the cluster-name extended argument for the controller-manager with the cluster's infra ID
func ObserveMasterURL(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	listers := genericListers.(InfrastructureLister)
	errs := []error{}
	masterURLPath := []string{"extendedArguments", "master"}
	previouslyObservedConfig := map[string]interface{}{}

	if currentMasterURL, _, _ := unstructured.NestedStringSlice(existingConfig, masterURLPath...); len(currentMasterURL) > 0 {
		if err := unstructured.SetNestedStringSlice(previouslyObservedConfig, currentMasterURL, masterURLPath...); err != nil {
			errs = append(errs, err)
		}
	}

	observedConfig := map[string]interface{}{}
	infrastructure, err := listers.InfrastructureLister().Get("cluster")
	if err != nil {
		if errors.IsNotFound(err) {
			recorder.Warningf("ObserveMasterURL", "Required infrastructures.%s/cluster not found", configv1.GroupName)
		}
		return previouslyObservedConfig, errs
	}
	// The infrastructureName value in infrastructure status is always present and cannot be changed during the
	// lifetime of the cluster.
	newMasterURL := infrastructure.Status.APIServerInternalURL
	if len(newMasterURL) == 0 {
		recorder.Warningf("ObserveMasterURL", "Value for infrastructureName in infrastructure.%s/cluster is blank", configv1.GroupName)
		return previouslyObservedConfig, errs
	}
	if err := unstructured.SetNestedStringSlice(observedConfig, []string{newMasterURL}, masterURLPath...); err != nil {
		errs = append(errs, err)
	}
	return observedConfig, errs
}
