package csidrivernodeservicecontroller

import (
	"crypto/sha256"
	"fmt"
	"strings"

	opv1 "github.com/openshift/api/operator/v1"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

func WithCABundleDaemonSetHook(
	configMapNamespace string,
	configMapName string,
	configMapInformer corev1.ConfigMapInformer,
) DaemonSetHookFunc {
	return func(_ *opv1.OperatorSpec, daemonSet *appsv1.DaemonSet) error {
		cm, err := configMapInformer.Lister().ConfigMaps(configMapNamespace).Get(configMapName)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get ConfigMap %s/%s: %v", configMapNamespace, configMapName, err)
		}
		_, ok := cm.Data["ca-bundle.crt"]
		if !ok {
			return nil
		}

		// Inject the CA bundle into the requested containers. This annotation is congruent to the
		// one used by CVO and the proxy hook) to inject proxy information.
		containerNamesString := daemonSet.Annotations["config.openshift.io/inject-proxy-cabundle"]
		err = v1helpers.InjectTrustedCAIntoContainers(
			&daemonSet.Spec.Template.Spec,
			configMapName,
			strings.Split(containerNamesString, ","),
		)
		if err != nil {
			return err
		}

		// Now that the CA bundle is inject into the containers, add an annotation to the daemonSet
		// so that it's rolled out when the ConfigMap content changes.
		inputHashes, err := resourcehash.MultipleObjectHashStringMapForObjectReferenceFromLister(
			configMapInformer.Lister(),
			nil,
			resourcehash.NewObjectRef().ForConfigMap().InNamespace(configMapNamespace).Named(configMapName),
		)
		if err != nil {
			return fmt.Errorf("invalid dependency reference: %w", err)
		}

		return addObjectHash(daemonSet, inputHashes)
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

		return addObjectHash(ds, inputHashes)
	}
}

func addObjectHash(daemonSet *appsv1.DaemonSet, inputHashes map[string]string) error {
	if daemonSet == nil {
		return fmt.Errorf("invalid daemonSet: %v", daemonSet)
	}
	if daemonSet.Annotations == nil {
		daemonSet.Annotations = map[string]string{}
	}
	if daemonSet.Spec.Template.Annotations == nil {
		daemonSet.Spec.Template.Annotations = map[string]string{}
	}
	for k, v := range inputHashes {
		annotationKey := fmt.Sprintf("operator.openshift.io/dep-%s", k)
		if len(annotationKey) > 63 {
			hash := sha256.Sum256([]byte(k))
			annotationKey = fmt.Sprintf("operator.openshift.io/dep-%x", hash)
			annotationKey = annotationKey[:63]
		}
		daemonSet.Annotations[annotationKey] = v
		daemonSet.Spec.Template.Annotations[annotationKey] = v
	}
	return nil
}
