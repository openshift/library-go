package node

import (
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
)

var minimumKubeletVersionConfigPath = "minimumKubeletVersion"

// ObserveKubeletMinimumVersion watches the node configuration and generates the minimumKubeletVersion
func ObserveMinimumKubeletVersion(genericListers configobserver.Listers, _ events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, errs []error) {
	defer func() {
		// Prune the observed config so that it only contains minimumKubeletVersion field.
		ret = configobserver.Pruned(ret, []string{minimumKubeletVersionConfigPath})
	}()
	nodeLister := genericListers.(NodeLister)
	configNode, err := nodeLister.NodeLister().Get("cluster")
	// we got an error so without the node object we are not able to determine minimumKubeletVersion
	if err != nil {
		// if config/v1/node/cluster object is not found, that can be treated as a non-error case, but raise a warning
		if apierrors.IsNotFound(err) {
			klog.Warningf("ObserveMinimumKubeletVersion: nodes.%s/cluster not found", configv1.GroupName)
		} else {
			errs = append(errs, err)
		}
		return existingConfig, errs
	}

	if configNode.Spec.MinimumKubeletVersion == "" {
		// in case minimum kubelet version is not set on cluster
		// return empty set of configs, this helps to unset the config
		// values related to the minimumKubeletVersion.
		// Also, ensures that this observer doesn't break cluster upgrades/downgrades
		return map[string]interface{}{}, errs
	}

	ret = map[string]interface{}{}
	if err := unstructured.SetNestedField(ret, configNode.Spec.MinimumKubeletVersion, minimumKubeletVersionConfigPath); err != nil {
		errs = append(errs, err)
	}

	return ret, errs
}
