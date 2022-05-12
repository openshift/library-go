package node

import (
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
)

type NodeLister interface {
	NodeLister() configlistersv1.NodeLister
}
