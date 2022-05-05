package common

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
)

// IsSNOCheckFnc creates a function that checks if the topology is SNO
// In case the err is nil, precheckSucceeded signifies whether the isSNO is valid.
// If precheckSucceeded is false, the isSNO return value does not reflect the cluster topology
// and defaults to the bool default value.
func IsSNOCheckFnc(infraInformer configv1informers.InfrastructureInformer) func() (isSNO, precheckSucceeded bool, err error) {
	return func() (isSNO, precheckSucceeded bool, err error) {
		if !infraInformer.Informer().HasSynced() {
			// Do not return transient error
			return false, false, nil
		}
		infraData, err := infraInformer.Lister().Get("cluster")
		if err != nil {
			return false, true, fmt.Errorf("Unable to list infrastructures.config.openshift.io/cluster object, unable to determine topology mode")
		}
		if infraData.Status.ControlPlaneTopology == "" {
			return false, true, fmt.Errorf("ControlPlaneTopology was not set, unable to determine topology mode")
		}

		return infraData.Status.ControlPlaneTopology == configv1.SingleReplicaTopologyMode, true, nil
	}
}
