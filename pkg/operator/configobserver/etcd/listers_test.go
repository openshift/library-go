package etcd

import (
	corelistersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

var _ ConfigMapLister = testLister{}
var _ EndpointsLister = testLister{}

type testLister struct {
	cmLister corelistersv1.ConfigMapLister
	epLister corelistersv1.EndpointsLister
}

func (l testLister) APIServerLister() configlistersv1.APIServerLister {
	return nil
}

func (l testLister) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return nil
}

func (l testLister) PreRunHasSynced() []cache.InformerSynced {
	return nil
}

func (l testLister) ConfigMapLister() corelistersv1.ConfigMapLister {
	return l.cmLister
}

func (l testLister) EndpointsLister() corelistersv1.EndpointsLister {
	return l.epLister
}
