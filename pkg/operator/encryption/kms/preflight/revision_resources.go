package preflight

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	preflightStaticPodResourcePrefix = "kms-preflight"
	preflightRevisionStatusPrefix    = "kms-preflight-revision-status"
	preflightRevisionControllerName  = "kms-preflight"
	revisionReadyAnnotation          = "operator.openshift.io/revision-ready"
)

func revisionResourceName(name string, revision int32) string {
	return fmt.Sprintf("%s-%d", name, revision)
}

func nextPreflightRevision(ctx context.Context, configMaps corev1client.ConfigMapsGetter, namespace string) (int32, error) {
	list, err := configMaps.ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to list preflight revision status configmaps: %w", err)
	}

	var maxRevision int32
	for _, cm := range list.Items {
		if !strings.HasPrefix(cm.Name, preflightRevisionStatusPrefix+"-") {
			continue
		}
		revision, err := strconv.ParseInt(strings.TrimPrefix(cm.Name, preflightRevisionStatusPrefix+"-"), 10, 32)
		if err != nil {
			continue
		}
		if int32(revision) > maxRevision {
			maxRevision = int32(revision)
		}
	}
	return maxRevision + 1, nil
}

func createPreflightRevision(
	ctx context.Context,
	configMaps corev1client.ConfigMapsGetter,
	secrets corev1client.SecretsGetter,
	recorder events.Recorder,
	namespace string,
	revision int32,
	reason string,
) ([]metav1.OwnerReference, error) {
	statusConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      revisionResourceName(preflightRevisionStatusPrefix, revision),
			Annotations: map[string]string{
				revisionReadyAnnotation: "true",
			},
			Labels: map[string]string{
				"operator.openshift.io/controller-instance-name": preflightRevisionControllerName,
			},
		},
		Data: map[string]string{
			"revision": strconv.FormatInt(int64(revision), 10),
			"reason":   reason,
		},
	}
	createdStatus, err := configMaps.ConfigMaps(namespace).Create(ctx, statusConfigMap, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create preflight revision status configmap: %w", err)
	}

	ownerRefs := []metav1.OwnerReference{{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Name:       createdStatus.Name,
		UID:        createdStatus.UID,
	}}

	revisionLabels := map[string]string{
		"operator.openshift.io/controller-instance-name": preflightRevisionControllerName,
	}
	if _, _, err = resourceapply.SyncConfigMapWithLabels(
		ctx,
		configMaps,
		recorder,
		namespace,
		preflightStaticPodResourcePrefix,
		namespace,
		revisionResourceName(preflightStaticPodResourcePrefix, revision),
		ownerRefs,
		revisionLabels,
	); err != nil {
		return nil, fmt.Errorf("failed to snapshot preflight pod configmap: %w", err)
	}

	if _, _, err = resourceapply.SyncSecretWithLabels(
		ctx,
		secrets,
		recorder,
		namespace,
		preflightEncryptionConfigSecretName,
		namespace,
		revisionResourceName(preflightEncryptionConfigSecretName, revision),
		ownerRefs,
		revisionLabels,
	); err != nil {
		return nil, fmt.Errorf("failed to snapshot preflight encryption config secret: %w", err)
	}

	return ownerRefs, nil
}

func deletePreflightRevisionResources(ctx context.Context, configMaps corev1client.ConfigMapsGetter, secrets corev1client.SecretsGetter, namespace string, revision int32) error {
	if revision == 0 {
		return nil
	}

	names := []string{
		revisionResourceName(preflightRevisionStatusPrefix, revision),
		revisionResourceName(preflightStaticPodResourcePrefix, revision),
	}
	for _, name := range names {
		err := configMaps.ConfigMaps(namespace).Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete configmap %s/%s: %w", namespace, name, err)
		}
	}

	secretName := revisionResourceName(preflightEncryptionConfigSecretName, revision)
	err := secrets.Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete secret %s/%s: %w", namespace, secretName, err)
	}
	return nil
}
