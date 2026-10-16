package controllermanager

import (
	configlistersv1alpha1 "github.com/openshift/client-go/config/listers/config/v1alpha1"
)

type ControllerManagerLister interface {
	ControllerManagerLister() configlistersv1alpha1.ControllerManagerLister
}
