package deployer

import (
	"context"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptionconfig"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

// MasterNodeProvider provides master nodes.
type MasterNodeProvider interface {
	// MasterNodeNames returns a list of nodes expected to run API server pods.
	MasterNodeNames() ([]string, error)

	// AddEventHandler registers handlers which are called whenever a resource
	// changes that can influence the result of Nodes.
	AddEventHandler(handler cache.ResourceEventHandler) []cache.InformerSynced
}

// RevisionLabelPodDeployer is a deployer abstraction meant for the pods with
// a label storing the deployed encryption config revision, like the pods created
// by the staticpod controllers.
type RevisionLabelPodDeployer struct {
	podClient    corev1client.PodInterface
	secretClient corev1client.SecretInterface

	targetNamespaceInformers informers.SharedInformerFactory

	nodeProvider MasterNodeProvider

	revisionLabel string

	cacheSynced []cache.InformerSynced
}

var (
	_ statemachine.Deployer = &RevisionLabelPodDeployer{}
)

// NewRevisionLabelPodDeployer creates a deployer abstraction meant for the pods with
// a label storing the deployed encryption config revision, like the pods created
// by the staticpod controllers.
//
// It revisiones and deployes the synchronized encryption-config from the
// operator namespace to the static pods. The last deployed encryption config is
// read from encryption-config-<revision>.
func NewRevisionLabelPodDeployer(
	revisionLabel string,
	targetNamespace string,
	namespaceInformers operatorv1helpers.KubeInformersForNamespaces,
	podClient corev1client.PodsGetter,
	secretClient corev1client.SecretsGetter,
	nodeProvider MasterNodeProvider,
) (*RevisionLabelPodDeployer, error) {
	return &RevisionLabelPodDeployer{
		podClient:                podClient.Pods(targetNamespace),
		secretClient:             secretClient.Secrets(targetNamespace),
		nodeProvider:             nodeProvider,
		targetNamespaceInformers: namespaceInformers.InformersFor(targetNamespace),
		revisionLabel:            revisionLabel,
	}, nil
}

// DeployedEncryptionConfigSecret returns the deployed encryption config and whether all
// instances of the operand have acknowledged it.
func (d *RevisionLabelPodDeployer) DeployedEncryptionConfigSecret(ctx context.Context) (secret *corev1.Secret, converged bool, err error) {
	nodes, err := d.nodeProvider.MasterNodeNames()
	if err != nil {
		return nil, false, err
	}
	if len(nodes) == 0 {
		return nil, false, nil
	}

	// do a live list so we never get confused about what revision we are on
	apiServerPods, err := d.podClient.List(ctx, metav1.ListOptions{LabelSelector: "apiserver=true"})
	if err != nil {
		return nil, false, err
	}

	revision, err := getAPIServerRevisionOfAllInstances(d.revisionLabel, nodes, apiServerPods.Items)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get converged static pod revision: %v", err)
	}
	if len(revision) == 0 {
		return nil, false, nil
	}

	s, err := d.secretClient.Get(ctx, encryptionconfig.EncryptionConfSecretName+"-"+revision, metav1.GetOptions{})
	if err != nil {
		// if encryption is not enabled at this revision or the secret was deleted, we should not error
		if errors.IsNotFound(err) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return s, true, nil
}

// AddEventHandler registers an event handler whenever the backing resource change
// that might influence the result of DeployedEncryptionConfigSecret.
func (d *RevisionLabelPodDeployer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	targetPodInformer := d.targetNamespaceInformers.Core().V1().Pods().Informer()
	if _, err := targetPodInformer.AddEventHandler(handler); err != nil {
		return nil, err
	}

	targetSecretsInformer := d.targetNamespaceInformers.Core().V1().Secrets().Informer()
	if _, err := targetSecretsInformer.AddEventHandler(handler); err != nil {
		return nil, err
	}

	d.cacheSynced = append([]cache.InformerSynced{
		targetPodInformer.HasSynced,
		targetSecretsInformer.HasSynced,
	}, d.nodeProvider.AddEventHandler(handler)...)

	return nil, nil
}

func (d *RevisionLabelPodDeployer) HasSynced() bool {
	allSynced := true
	for i := range d.cacheSynced {
		if !d.cacheSynced[i]() {
			allSynced = false
			break
		}
	}
	return allSynced
}

// getAPIServerRevisionOfAllInstances attempts to find the current revision that
// the API servers are running at.  If all API servers have not converged onto a
// a single revision, it returns the empty string and possibly an error.
// Converged can be defined as:
//  1. All running pods are ready and at the same revision
//  2. All master nodes have a running pod
//  3. There are no pending or unknown pods
//  4. We tolerate pods in Succeeded or Failed phase only if their revision <= the running pods
//     It turns out that when a node dies or is disconnected from the rest of the cluster, Kubernetes (kubelet) applies a policy for setting the phase of all Pods on the lost node to Failed.
//     Pods in the Failed state cannot transition back to Running state.
//     In addition, failed Pods are note GC'ed. The API objects remain in the cluster's API until a human or controller process explicitly removes them.
//     See the following for more:
//     https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
//     https://bugzilla.redhat.com/show_bug.cgi?id=2000276
//
// Once a converged revision has been determined, it can be used to determine
// what encryption config state has been successfully observed by the API servers.
// It assumes that podClient is doing live lookups against the cluster state.
func getAPIServerRevisionOfAllInstances(revisionLabel string, nodes []string, apiServerPods []corev1.Pod) (string, error) {
	good, bad, progressing, err := categorizePods(apiServerPods)
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
	if len(revision) == 0 {
		revision = "0"
	}

	// make sure all expected nodes are there
	missingNodes := []string{}
	for _, n := range nodes {
		if !goodNodes.Has(n) {
			missingNodes = append(missingNodes, n)
		}
	}
	if len(missingNodes) > 0 {
		return "", nil // we are still progressing
	}

	if len(revision) == 0 {
		return "", nil
	}
	revisionNum, err := strconv.Atoi(revision)
	if err != nil {
		return "", fmt.Errorf("api server has invalid revision: %v", err)
	}

	for _, failedRevision := range failingRevisions.List() { // iterate in defined order
		if len(failedRevision) == 0 {
			// these will never be bigger than revisionNum
			continue
		}
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
	if len(pods) == 0 {
		return nil, nil, true, err
	}
	for _, apiServerPod := range pods {
		switch phase := apiServerPod.Status.Phase; phase {
		case corev1.PodRunning:
			if !podReady(apiServerPod) {
				return nil, nil, true, nil // pods are not fully ready
			}
			goodPod := apiServerPod // shallow copy because apiServerPod is bound loop var
			good = append(good, &goodPod)
		case corev1.PodPending:
			return nil, nil, true, nil // pods are not fully ready
		case corev1.PodUnknown:
			return nil, nil, false, fmt.Errorf("api server pod %s in unknown phase", apiServerPod.Name)
		case corev1.PodSucceeded, corev1.PodFailed:
			// handle failed pods carefully to make sure things are healthy
			// since the API server should never exit, a succeeded pod is considered as failed
			badPod := apiServerPod // shallow copy because apiServerPod is bound loop var
			bad = append(bad, &badPod)
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
