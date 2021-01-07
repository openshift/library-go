package csidrivercontrollerservicecontroller

import (
	"strings"

	appsv1 "k8s.io/api/apps/v1"

	opv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/csi/csiconfigobservercontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// WithObservedProxyDeploymentHook creates a deployment hook that injects into the deployment's containers the observed proxy config.
func WithObservedProxyDeploymentHook() DeploymentHookFunc {
	return func(opSpec *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		containerNamesString := deployment.Annotations["config.openshift.io/inject-proxy"]
		err := v1helpers.InjectObservedProxyIntoContainers(
			&deployment.Spec.Template.Spec,
			strings.Split(containerNamesString, ","),
			opSpec.ObservedConfig.Raw,
			csiconfigobservercontroller.ProxyConfigPath()...,
		)
		return err
	}
}
