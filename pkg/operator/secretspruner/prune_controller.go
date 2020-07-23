package secretspruner

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/openshift/library-go/pkg/controller/factory"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informer "k8s.io/client-go/informers/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	encryptionsecrets "github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// SecretRevisionPruneController is a controller that watches the operand pods and deletes old
// revisioned secrets that are not used anymore.
type SecretRevisionPruneController struct {
	targetNamespace string
	secretPrefixes  []string
	podSelector     labels.Selector

	secretGetter   corev1client.SecretsGetter
	podInformer    corev1informer.PodInformer
	secretInformer corev1informer.SecretInformer
}

const (
	numOldRevisionsToPreserve = 5
)

// NewSecretRevisionPruneController creates a new pruning controller
func NewSecretRevisionPruneController(
	targetNamespace string,
	secretPrefixes []string,
	podLabelSelector labels.Selector,
	secretGetter corev1client.SecretsGetter,
	informers v1helpers.KubeInformersForNamespaces,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &SecretRevisionPruneController{
		targetNamespace: targetNamespace,
		secretPrefixes:  secretPrefixes,
		podSelector:     podLabelSelector,

		secretGetter:   secretGetter,
		podInformer:    informers.InformersFor(targetNamespace).Core().V1().Pods(),
		secretInformer: informers.InformersFor(targetNamespace).Core().V1().Secrets(),
	}

	return factory.New().WithInformers(
		c.podInformer.Informer(),
		c.secretInformer.Informer(),
	).WithSync(c.sync).ToController("SecretRevisionPruneController", eventRecorder.WithComponentSuffix("secret-revision-prune-controller"))
}

func (c *SecretRevisionPruneController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	klog.V(5).Infof("revision pruner sync for ns/%s", c.targetNamespace)

	pods, err := c.podInformer.Lister().Pods(c.targetNamespace).List(c.podSelector)
	if err != nil {
		return err
	}

	minRevision := minPodRevision(pods)
	if minRevision == 0 {
		return nil
	}

	secrets, err := c.secretInformer.Lister().Secrets(c.targetNamespace).List(labels.Everything())
	if err != nil {
		return err
	}

	for _, s := range secretsToBePruned(minRevision, c.secretPrefixes, secrets) {
		klog.V(4).Infof("Pruning old secret %q", s.Name)

		// remove finalizer
		retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			s, err := c.secretGetter.Secrets(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					return nil
				}
				return err
			}

			// remove finalizer
			newFinalizers := make([]string, 0, len(s.Finalizers))
			for _, f := range s.Finalizers {
				if f == encryptionsecrets.EncryptionSecretFinalizer {
					continue
				}
				newFinalizers = append(newFinalizers, f)
			}
			if len(newFinalizers) == len(s.Finalizers) {
				return nil
			}
			s.Finalizers = newFinalizers

			_, err = c.secretGetter.Secrets(s.Namespace).Update(ctx, s, metav1.UpdateOptions{})
			return err
		})

		if err := c.secretGetter.Secrets(s.Namespace).Delete(ctx, s.Name, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func secretsToBePruned(minRevision int, secretPrefixes []string, secrets []*corev1.Secret) []*corev1.Secret {
	// filter secrets by prefix and by revision < minRevision
	filtered := map[int][]*corev1.Secret{}
	for _, s := range secrets {
		for _, p := range secretPrefixes {
			if strings.HasPrefix(s.Name, p) {
				comps := strings.SplitAfter(s.Name, "-")
				if len(comps) == 1 {
					// skip, we cannot derive a revision
					klog.Warningf("Unexpected %q prefixed secret without a dash: %q", p, s.Name)
					break
				}
				revString := comps[len(comps)-1]
				rev, err := strconv.ParseInt(revString, 10, 32)
				if err != nil {
					// skip, we cannot derive a revision
					klog.Warningf("Unexpected %q prefixed secret %q with invalid trailing revision: %v", p, s.Name, err)
					break
				}

				if int(rev) >= minRevision {
					break
				}

				filtered[int(rev)] = append(filtered[int(rev)], s)

				break
			}
		}
	}

	sortedRevs := sortedRevisionsRecentLast(filtered)
	if len(sortedRevs) < numOldRevisionsToPreserve {
		// not enough old revisions found, nothing to prune
		return nil
	}

	revsToBePruned := sortedRevs[:len(sortedRevs)-numOldRevisionsToPreserve]

	ret := []*corev1.Secret{}
	for _, r := range revsToBePruned {
		secrets := filtered[r]
		for _, s := range secrets {
			ret = append(ret, s)
		}
	}

	return ret
}

func sortedRevisionsRecentLast(revs map[int][]*corev1.Secret) []int {
	ret := make([]int, 0, len(revs))
	for r := range revs {
		ret = append(ret, r)
	}
	sort.Ints(ret)
	return ret
}

func minPodRevision(pods []*corev1.Pod) int {
	minRevision := int64(0)
	for _, p := range pods {
		l := p.Labels["revision"]
		if len(l) == 0 {
			continue
		}
		rev, err := strconv.ParseInt(l, 10, 32)
		if err != nil || rev < 0 {
			klog.Warningf("Invalid revision label on pod %s: %q", p.Name, l)
			continue
		}
		if minRevision == 0 || rev < minRevision {
			minRevision = rev
		}
	}
	return int(minRevision)
}
