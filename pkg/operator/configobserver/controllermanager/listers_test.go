package controllermanager

import (
	"k8s.io/client-go/tools/cache"

	configlistersv1alpha1 "github.com/openshift/client-go/config/listers/config/v1alpha1"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

type testLister struct {
	controllerManagerLister configlistersv1alpha1.ControllerManagerLister
}

func (l testLister) ControllerManagerLister() configlistersv1alpha1.ControllerManagerLister {
	return l.controllerManagerLister
}

func (l testLister) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return nil
}

func (l testLister) PreRunHasSynced() []cache.InformerSynced {
	return nil
}
