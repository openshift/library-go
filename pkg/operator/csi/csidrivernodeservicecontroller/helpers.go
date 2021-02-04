package csidrivernodeservicecontroller

import (
	"strings"

	opv1 "github.com/openshift/api/operator/v1"
	appsv1 "k8s.io/api/apps/v1"

	"github.com/openshift/library-go/pkg/operator/csi/csiconfigobservercontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// WithObservedProxyDaemonSetHook creates a hook that injects into the daemonSet's containers the observed proxy config.
func WithObservedProxyDaemonSetHook() DaemonSetHookFunc {
	return func(opSpec *opv1.OperatorSpec, daemonSet *appsv1.DaemonSet) error {
		containerNamesString := daemonSet.Annotations["config.openshift.io/inject-proxy"]
		err := v1helpers.InjectObservedProxyIntoContainers(
			&daemonSet.Spec.Template.Spec,
			strings.Split(containerNamesString, ","),
			opSpec.ObservedConfig.Raw,
			csiconfigobservercontroller.ProxyConfigPath()...,
		)
		return err
	}
}
