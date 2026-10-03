package revisionpruner

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informer "k8s.io/client-go/informers/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"
)

// ConfigMapRevisionPruneController is a controller that watches the operand pods and deletes old
// revisioned configmaps that are not used anymore.
type ConfigMapRevisionPruneController struct {
	targetNamespace   string
	configMapPrefixes []string
	podSelector       labels.Selector

	configMapGetter   corev1client.ConfigMapsGetter
	podInformer       corev1informer.PodInformer
	configMapInformer corev1informer.ConfigMapInformer
}

const (
	numOldRevisionsToPreserve = 5
)

// NewConfigMapRevisionPruneController creates a new pruning controller
func NewConfigMapRevisionPruneController(
	targetNamespace string,
	configMapPrefixes []string,
	podLabelSelector labels.Selector,
	configMapGetter corev1client.ConfigMapsGetter,
	informers v1helpers.KubeInformersForNamespaces,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &ConfigMapRevisionPruneController{
		targetNamespace:   targetNamespace,
		configMapPrefixes: configMapPrefixes,
		podSelector:       podLabelSelector,

		configMapGetter:   configMapGetter,
		podInformer:       informers.InformersFor(targetNamespace).Core().V1().Pods(),
		configMapInformer: informers.InformersFor(targetNamespace).Core().V1().ConfigMaps(),
	}

	return factory.New().
		WithInformers(
			c.podInformer.Informer(),
			c.configMapInformer.Informer(),
		).
		WithSync(c.sync).
		ToController(
			"ConfigMapRevisionPruneController",
			eventRecorder.WithComponentSuffix("configmap-revision-prune-controller"),
		)
}

func (c *ConfigMapRevisionPruneController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	klog.V(5).Infof("revision pruner sync for namespace: %s", c.targetNamespace)

	pods, err := c.podInformer.Lister().Pods(c.targetNamespace).List(c.podSelector)
	if err != nil {
		return err
	}

	minRevision := minPodRevision(pods)
	if minRevision == 0 {
		return nil
	}

	configMaps, err := c.configMapInformer.Lister().ConfigMaps(c.targetNamespace).List(labels.Everything())
	if err != nil {
		return err
	}

	for _, cm := range configMapsToBePruned(minRevision, c.configMapPrefixes, configMaps) {
		klog.V(4).Infof("pruning old revision ConfigMap %s/%s", cm.Namespace, cm.Name)

		if err := c.configMapGetter.ConfigMaps(cm.Namespace).Delete(ctx, cm.Name, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func configMapsToBePruned(minRevision int, configMapPrefixes []string, configMaps []*corev1.ConfigMap) []*corev1.ConfigMap {
	filtered := map[string]map[int][]*corev1.ConfigMap{}
	for _, cm := range configMaps {
		for _, pre := range configMapPrefixes {
			r, found := strings.CutPrefix(cm.Name, pre)
			if found {
				rev, err := strconv.Atoi(r)
				if err != nil || rev <= 0 {
					klog.Warningf("revision configmap %s/%s with prefix %q has invalid suffix: %v", cm.Namespace, cm.Name, pre, err)
					break
				}

				if rev < minRevision {
					if filtered[pre] == nil {
						filtered[pre] = map[int][]*corev1.ConfigMap{}
					}
					filtered[pre][rev] = append(filtered[pre][rev], cm)
				}

				break
			}
		}
	}

	prune := []*corev1.ConfigMap{}
	for _, pre := range configMapPrefixes {
		sorted := slices.Sorted(maps.Keys(filtered[pre]))
		if len(sorted) <= numOldRevisionsToPreserve {
			continue
		}

		for _, rev := range sorted[:len(sorted)-numOldRevisionsToPreserve] {
			prune = append(prune, filtered[pre][rev]...)
		}
	}

	return prune
}

func minPodRevision(pods []*corev1.Pod) int {
	min := 0
	for p := range pods {
		l := pods[p].Labels["revision"]
		if l == "" {
			continue
		}
		r, err := strconv.Atoi(l)
		if err != nil || r <= 0 {
			klog.Warningf("invalid revision label on pod %s/%s: %q", pods[p].Namespace, pods[p].Name, l)
			continue
		}
		if r < min || min == 0 {
			min = r
		}
	}
	return min
}
