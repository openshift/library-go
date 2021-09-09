package csidrivernodeservicecontroller

import (
	"crypto/sha256"
	"fmt"
	"strings"

	opv1 "github.com/openshift/api/operator/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/client-go/informers/core/v1"

	"github.com/openshift/library-go/pkg/operator/csi/csiconfigobservercontroller"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehash"
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

// WithSecretHashAnnotationHook creates a DaemonSet hook that annotates a DaemonSet with a secret's hash.
func WithSecretHashAnnotationHook(
	namespace string,
	secretName string,
	secretInformer corev1.SecretInformer,
) DaemonSetHookFunc {
	return func(_ *opv1.OperatorSpec, ds *appsv1.DaemonSet) error {
		inputHashes, err := resourcehash.MultipleObjectHashStringMapForObjectReferenceFromLister(
			nil,
			secretInformer.Lister(),
			resourcehash.NewObjectRef().ForSecret().InNamespace(namespace).Named(secretName),
		)
		if err != nil {
			return fmt.Errorf("invalid dependency reference: %w", err)
		}
		if ds.Annotations == nil {
			ds.Annotations = map[string]string{}
		}
		if ds.Spec.Template.Annotations == nil {
			ds.Spec.Template.Annotations = map[string]string{}
		}
		for k, v := range inputHashes {
			annotationKey := fmt.Sprintf("operator.openshift.io/dep-%s", k)
			if len(annotationKey) > 63 {
				hash := sha256.Sum256([]byte(k))
				annotationKey = fmt.Sprintf("operator.openshift.io/dep-%x", hash)
				annotationKey = annotationKey[:63]
			}
			ds.Annotations[annotationKey] = v
			ds.Spec.Template.Annotations[annotationKey] = v
		}
		return nil
	}
}
