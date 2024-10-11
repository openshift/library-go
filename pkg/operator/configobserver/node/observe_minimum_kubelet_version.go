package node

import (
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
)

type minimumKubeletVersionObserver struct{}

// NewMinimumKubeletVersionObserver is used to create ObserveConfigFunc that can be used with an configobservation controller to trigger
// changes to different arg val pairs in observedConfig.* fields and update them on the basis of current minimum kubelet version.
// ShouldSuppressConfigUpdatesFunc is used to pass a function that returns a boolean and config updates by the observer function are
// only passed iff the bool value is false, it is helpful to gate the config updates in case a pre-req condition is not satisfied.
func NewMinimumKubeletVersionObserver() configobserver.ObserveConfigFunc {
	ret := minimumKubeletVersionObserver{}
	return ret.observe
}

// ObserveKubeletMinimumVersion watches the node configuration and generates the minimumKubeletVersion
func (*minimumKubeletVersionObserver) observe(genericListers configobserver.Listers, _ events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	out := map[string]interface{}{}
	errs := []error{}

	listers := genericListers.(NodeLister)
	configNode, err := listers.NodeLister().Get("cluster")
	// we got an error so without the node object we are not able to determine worker latency profile
	if err != nil {
		// if config/v1/node/cluster object is not found, that can be treated as a non-error case
		if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		} else { // but raise a warning
			klog.Warningf("nodes.config.openshift.io/cluster object could not be found")
		}
		return existingConfig, errs
	}

	// TODO: not sure if this is right
	if configNode.Spec.MinimumKubeletVersion == "" {
		// in case minimum kubelet version is not set on cluster
		// return empty set of configs, this helps to unset the config
		// values related to the latency profile in case we transition
		// from anyProfile -> "" (empty); also, ensures that this observer
		// to not break cluster upgrades/downgrades
		return map[string]interface{}{}, errs
	}

	if err := unstructured.SetNestedField(out, configNode.Spec.MinimumKubeletVersion, "minimumKubeletVersion"); err != nil {
		errs = append(errs, err)
	}

	return out, errs
}
