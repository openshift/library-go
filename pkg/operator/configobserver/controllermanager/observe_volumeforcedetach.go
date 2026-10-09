package controllermanager

import (
	"reflect"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
)

// volumeForceDetachFlagPath is the default location in observedConfig for the
// kube-controller-manager CLI flag derived from
// ControllerManager.spec.volumeForceDetach.
var volumeForceDetachFlagPath = []string{"extendedArguments", "disable-force-detach-on-timeout"}

// ObserveVolumeForceDetach observes the ControllerManager.spec.volumeForceDetach
// field and sets the extendedArguments.disable-force-detach-on-timeout flag of the
// observed config. The policy is mapped to the disable-style kube-controller-manager
// flag: "OnOutOfServiceTaintOnly" maps to "true" (force detach on unmount timeout
// disabled) and "OnUnmountTimeout" maps to "false".
func ObserveVolumeForceDetach(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
	return innerObserveVolumeForceDetach(genericListers, recorder, existingConfig, volumeForceDetachFlagPath)
}

func innerObserveVolumeForceDetach(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}, flagPath []string) (ret map[string]interface{}, _ []error) {
	defer func() {
		// Prune the observed config so that it only contains fields specific to this observer.
		ret = configobserver.Pruned(ret, flagPath)
	}()

	listers := genericListers.(ControllerManagerLister)
	errs := []error{}

	// grab the current flag value to later check whether it was updated
	currentFlag, _, err := unstructured.NestedStringSlice(existingConfig, flagPath...)
	if err != nil {
		errs = append(errs, err)
		// keep going on read error from existing config
	}

	controllerManager, err := listers.ControllerManagerLister().Get("cluster")
	if errors.IsNotFound(err) {
		// no opinion: emit nothing so the operator default applies
		return map[string]interface{}{}, errs
	}
	if err != nil {
		// return existingConfig here in case err is just a transient error so
		// that we don't rewrite the config that was observed previously
		return existingConfig, append(errs, err)
	}

	// when the field is unset the user has no opinion; emit nothing so the
	// operator default applies
	if controllerManager.Spec == nil || controllerManager.Spec.VolumeForceDetach == "" {
		return map[string]interface{}{}, errs
	}

	var flagValue string
	switch controllerManager.Spec.VolumeForceDetach {
	case configv1alpha1.VolumeForceDetachOnOutOfServiceTaintOnly:
		flagValue = "true"
	case configv1alpha1.VolumeForceDetachOnUnmountTimeout:
		flagValue = "false"
	default:
		// Note: In case new policies are added in the future in openshift/api
		// this could break cluster upgrades although we're not passing an error here
		// to ensure that ConfigObservationController doesn't reach degraded state.
		klog.Warningf("unsupported volumeForceDetach policy found in controllermanager.config.openshift.io/cluster Spec.VolumeForceDetach = %v", controllerManager.Spec.VolumeForceDetach)
		return existingConfig, errs
	}

	observedConfig := map[string]interface{}{}
	observedFlag := []string{flagValue}
	if err := unstructured.SetNestedStringSlice(observedConfig, observedFlag, flagPath...); err != nil {
		return existingConfig, append(errs, err)
	}

	if !reflect.DeepEqual(observedFlag, currentFlag) {
		recorder.Eventf("ObserveVolumeForceDetach", "disable-force-detach-on-timeout changed to %q", observedFlag)
	}

	return observedConfig, errs
}
