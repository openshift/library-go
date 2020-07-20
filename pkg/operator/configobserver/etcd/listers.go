package etcd

import (
	corelistersv1 "k8s.io/client-go/listers/core/v1"
)

type ConfigmapLister interface {
	ConfigmapLister() corelistersv1.ConfigMapLister
}

type EndpointsLister interface {
	EndpointsLister() corelistersv1.EndpointsLister
}
