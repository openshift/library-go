package deployer

import (
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptionconfig"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

type StaticPodDeployer struct {
	podClient      corev1client.PodInterface
	secretClient   corev1client.SecretInterface
	operatorClient operatorv1helpers.StaticPodOperatorClient

	targetNamespaceInformers informers.SharedInformerFactory
}

var _ statemachine.Deployer = &StaticPodDeployer{}

// NewStaticPodDeployer create a deployer abstraction meant for the staticpod controllers. It copies
// the encryption-config-<targetNamespace> from openshift-config-managed namespace to the target namespace
// as encryption-config. From there it is revisioned and deployed to the static pods. The last
// deployed encryption config is read from encryption-config-<revision>.
//
// For testing, resourceSyncer might be nil.
func NewStaticPodDeployer(
	targetNamespace string,
	namespaceInformers operatorv1helpers.KubeInformersForNamespaces,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
	podClient corev1client.PodsGetter,
	secretClient corev1client.SecretsGetter,
	operatorClient operatorv1helpers.StaticPodOperatorClient,
) (*StaticPodDeployer, error) {
	if resourceSyncer != nil {
		if err := resourceSyncer.SyncSecret(
			resourcesynccontroller.ResourceLocation{Namespace: targetNamespace, Name: encryptionconfig.EncryptionConfSecretName},
			resourcesynccontroller.ResourceLocation{Namespace: "openshift-config-managed", Name: fmt.Sprintf("%s-%s", encryptionconfig.EncryptionConfSecretName, targetNamespace)},
		); err != nil {
			return nil, err
		}
	}

	return &StaticPodDeployer{
		podClient:                podClient.Pods(targetNamespace),
		secretClient:             secretClient.Secrets(targetNamespace),
		operatorClient:           operatorClient,
		targetNamespaceInformers: namespaceInformers.InformersFor(targetNamespace),
	}, nil
}

// DeployedEncryptionConfigSecret returns the deployed encryption config and whether all
// instances of the operand have acknowledged it.
func (d *StaticPodDeployer) DeployedEncryptionConfigSecret() (secret *corev1.Secret, converged bool, err error) {
	_, status, _, err := d.operatorClient.GetStaticPodOperatorState()
	if err != nil {
		return nil, false, err
	}
	if status == nil || len(status.NodeStatuses) == 0 {
		return nil, false, nil
	}

	revision, err := getAPIServerRevisionOfAllInstances("revision", status.NodeStatuses, d.podClient)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get converged static pod revision: %v", err)
	}
	if len(revision) == 0 {
		return nil, false, nil
	}

	s, err := d.secretClient.Get(encryptionconfig.EncryptionConfSecretName+"-"+revision, metav1.GetOptions{})
	if err != nil {
		// if encryption is not enabled at this revision or the secret was deleted, we should not error
		if errors.IsNotFound(err) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return s, true, nil
}

// AddEventHandler registers a event handler whenever the backing resource change
// that might influence the result of DeployedEncryptionConfigSecret.
func (d *StaticPodDeployer) AddEventHandler(handler cache.ResourceEventHandler) []cache.InformerSynced {
	targetPodInformer := d.targetNamespaceInformers.Core().V1().Pods().Informer()
	targetPodInformer.AddEventHandler(handler)

	targetSecretsInformer := d.targetNamespaceInformers.Core().V1().Secrets().Informer()
	targetSecretsInformer.AddEventHandler(handler)

	d.operatorClient.Informer().AddEventHandler(handler)

	return []cache.InformerSynced{
		targetPodInformer.HasSynced,
		targetSecretsInformer.HasSynced,
		d.operatorClient.Informer().HasSynced,
	}
}

// getAPIServerRevisionOfAllInstances attempts to find the current revision that
// the API servers are running at.  If all API servers have not converged onto a
// a single revision, it returns the empty string and possibly an error.
// Converged can be defined as:
//   1. All running pods are ready and at the same revision
//   2. All master nodes have a running pod
//   3. There are no pending or unknown pods
//   4. All succeeded and failed pods have revisions that are before the running pods
// Once a converged revision has been determined, it can be used to determine
// what encryption config state has been successfully observed by the API servers.
// It assumes that podClient is doing live lookups against the cluster state.
func getAPIServerRevisionOfAllInstances(revisionLabel string, nodes []operatorv1.NodeStatus, podClient corev1client.PodInterface) (string, error) {
	// do a live list so we never get confused about what revision we are on
	apiServerPods, err := podClient.List(metav1.ListOptions{LabelSelector: "apiserver=true"})
	if err != nil {
		return "", err
	}

	good, bad, progressing, err := categorizePods(apiServerPods.Items)
	if err != nil {
		return "", err
	}
	if progressing {
		return "", nil
	}

	goodRevisions := revisions(revisionLabel, good)
	goodNodes := nodeNames(good)
	failingRevisions := revisions(revisionLabel, bad)

	if len(goodRevisions) != 1 {
		return "", nil // api servers have not converged onto a single revision
	}
	revision, _ := goodRevisions.PopAny()

	if failingRevisions.Has(revision) {
		return "", fmt.Errorf("api server revision %s has both running and failed pods", revision)
	}

	// make sure all expected nodes are there
	missingNodes := []string{}
	for _, n := range nodes {
		if !goodNodes.Has(n.NodeName) {
			missingNodes = append(missingNodes, n.NodeName)
		}
	}
	if len(missingNodes) > 0 {
		return "", fmt.Errorf("api server pods missing for nodes %v", missingNodes)
	}

	revisionNum, err := strconv.Atoi(revision)
	if err != nil {
		return "", fmt.Errorf("api server has invalid revision: %v", err)
	}

	for _, failedRevision := range failingRevisions.List() { // iterate in defined order
		failedRevisionNum, err := strconv.Atoi(failedRevision)
		if err != nil {
			return "", fmt.Errorf("api server has invalid failed revision: %v", err)
		}
		if failedRevisionNum > revisionNum { // TODO can this dead lock?
			return "", fmt.Errorf("api server has failed revision %v which is newer than running revision %v", failedRevisionNum, revisionNum)
		}
	}

	return revision, nil
}

func revisions(revisionLabel string, pods []*corev1.Pod) sets.String {
	ret := sets.NewString()
	for _, p := range pods {
		ret.Insert(p.Labels[revisionLabel])
	}
	return ret
}

func nodeNames(pods []*corev1.Pod) sets.String {
	ret := sets.NewString()
	for _, p := range pods {
		ret.Insert(p.Spec.NodeName)
	}
	return ret
}

func categorizePods(pods []corev1.Pod) (good []*corev1.Pod, bad []*corev1.Pod, progressing bool, err error) {
	for _, apiServerPod := range pods {
		switch phase := apiServerPod.Status.Phase; phase {
		case corev1.PodRunning:
			if !podReady(apiServerPod) {
				return nil, nil, true, nil // pods are not fully ready
			}
			good = append(good, &apiServerPod)
		case corev1.PodPending:
			return nil, nil, true, nil // pods are not fully ready
		case corev1.PodUnknown:
			return nil, nil, false, fmt.Errorf("api server pod %s in unknown phase", apiServerPod.Name)
		case corev1.PodSucceeded, corev1.PodFailed:
			// handle failed pods carefully to make sure things are healthy
			// since the API server should never exit, a succeeded pod is considered as failed
			bad = append(bad, &apiServerPod)
		default:
			// error in case new unexpected phases get added
			return nil, nil, false, fmt.Errorf("api server pod %s has unexpected phase %v", apiServerPod.Name, phase)
		}
	}
	return good, bad, false, nil
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
