package apiserver

import (
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"k8s.io/client-go/tools/cache"
)

type testLister struct {
	apiLister configlistersv1.APIServerLister
}

func (l testLister) APIServerLister() configlistersv1.APIServerLister {
	return l.apiLister
}

func (l testLister) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return nil
}

func (l testLister) PreRunHasSynced() []cache.InformerSynced {
	return nil
}
