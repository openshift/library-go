package csidrivercontrollerservicecontroller

import (
	"crypto/sha256"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/client-go/informers/core/v1"

	opv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/csi/csiconfigobservercontroller"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehash"
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

// With SecretHashAnnotationHook creates a deployment hook that annotates a Deployment with a secret's hash.
func WithSecretHashAnnotationHook(
	namespace string,
	secretName string,
	secretInformer corev1.SecretInformer,
) DeploymentHookFunc {
	return func(opSpec *opv1.OperatorSpec, deployment *appsv1.Deployment) error {
		inputHashes, err := resourcehash.MultipleObjectHashStringMapForObjectReferenceFromLister(
			nil,
			secretInformer.Lister(),
			resourcehash.NewObjectRef().ForSecret().InNamespace(namespace).Named(secretName),
		)
		if err != nil {
			return fmt.Errorf("invalid dependency reference: %w", err)
		}
		if deployment.Annotations == nil {
			deployment.Annotations = map[string]string{}
		}
		if deployment.Spec.Template.Annotations == nil {
			deployment.Spec.Template.Annotations = map[string]string{}
		}
		for k, v := range inputHashes {
			annotationKey := fmt.Sprintf("operator.openshift.io/dep-%s", k)
			if len(annotationKey) > 63 {
				hash := sha256.Sum256([]byte(k))
				annotationKey = fmt.Sprintf("operator.openshift.io/dep-%x", hash)
				annotationKey = annotationKey[:63]
			}
			deployment.Annotations[annotationKey] = v
			deployment.Spec.Template.Annotations[annotationKey] = v
		}
		return nil
	}
}
