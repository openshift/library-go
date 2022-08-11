package onepodpernodeccontroller

import (
	"context"
	"strings"
	"time"

	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	coreinformersv1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

// OnePodPerNodeController is a generic controller that ensures that only one pod is scheduled per node.
//
// This is useful in cases where topology spread is desired.  We have encountered cases where the scheduler is
// misscheduling a pod.  The scheduler still does need to be fixed, but this keeps the platform from failing.
type OnePodPerNodeController struct {
	name           string
	operatorClient v1helpers.OperatorClientWithFinalizers
	clock          clock.Clock

	namespace       string
	kubeClient      kubernetes.Interface
	podLister       corev1lister.PodLister
	podSelector     labels.Selector
	minReadySeconds int32 // this comes from your deployment, daemonset, etc
	recorder        events.Recorder
}

func NewOnePodPerNodeController(
	name string,
	namespace string,
	podSelector *metav1.LabelSelector,
	minReadySeconds int32, // this comes from your deployment, daemonset, etc
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	kubeClient kubernetes.Interface,
	podInformer coreinformersv1.PodInformer,
) factory.Controller {
	selector, err := metav1.LabelSelectorAsSelector(podSelector)
	if err != nil {
		panic(err)
	}

	c := &OnePodPerNodeController{
		name:           name,
		operatorClient: operatorClient,
		clock:          clock.RealClock{},
		recorder:       recorder,

		namespace:       namespace,
		podSelector:     selector,
		minReadySeconds: minReadySeconds,
		kubeClient:      kubeClient,
		podLister:       podInformer.Lister(),
	}

	return factory.New().WithInformers(
		podInformer.Informer(),
	).WithSync(
		c.sync,
	).ResyncEvery(
		time.Minute,
	).WithSyncDegradedOnError(
		operatorClient,
	).ToController(
		c.name,
		recorder.WithComponentSuffix(strings.ToLower(name)+"-one-pod-per-node-"),
	)
}

func (c *OnePodPerNodeController) Name() string {
	return c.name
}

func (c *OnePodPerNodeController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	klog.V(4).Infof("sync")
	opSpec, _, _, err := c.operatorClient.GetOperatorState()
	if apierrors.IsNotFound(err) && management.IsOperatorRemovable() {
		return nil
	}
	if err != nil {
		return err
	}

	if opSpec.ManagementState != opv1.Managed {
		return nil
	}

	return c.syncManaged(ctx, syncContext)
}

func (c *OnePodPerNodeController) syncManaged(ctx context.Context, syncContext factory.SyncContext) error {
	klog.V(4).Infof("syncManaged")

	matchingPods, err := c.podLister.Pods(c.namespace).List(c.podSelector)
	if err != nil {
		return err
	}

	nodesToPods := map[string][]*corev1.Pod{}
	for i := range matchingPods {
		pod := matchingPods[i]

		// don't consider deleted pods, they are shutting down and need grace to come down.
		if pod.DeletionTimestamp != nil {
			continue
		}
		// don't consider unscheduled pods
		if len(pod.Spec.NodeName) == 0 {
			continue
		}
		// don't consider unavailable pods, they cannot reliably handle requests
		if !isPodAvailable(pod, c.minReadySeconds, metav1.Time{Time: c.clock.Now()}) {
			continue
		}
		nodesToPods[pod.Spec.NodeName] = append(nodesToPods[pod.Spec.NodeName], pod)
	}

	for _, pods := range nodesToPods {
		if len(pods) <= 1 {
			continue
		}

		// we choose to delete the oldest, because if a deployment, daemonset, or other controller is rolling out a newer
		// level, the newer pod will be the desired pod and the older pod is the not-desired pod.
		oldestPod := pods[0]
		for i := 1; i < len(pods); i++ {
			currPod := pods[i]
			if currPod.CreationTimestamp.Before(&oldestPod.CreationTimestamp) {
				oldestPod = currPod
			}
		}

		displayPodString := sets.String{}
		for _, pod := range pods {
			displayPodString.Insert("pod/" + pod.Name)
		}

		// we use eviction, not deletion.  Eviction honors PDBs.
		c.recorder.Warningf("MalscheduledPod",
			"%v should be one per node, but all were placed on node/%v; evicting pod/%v",
			strings.Join(displayPodString.List(), " "),
			oldestPod.Spec.NodeName,
			oldestPod.Name,
		)
		err := c.kubeClient.CoreV1().Pods(oldestPod.Namespace).EvictV1(ctx,
			&policyv1.Eviction{
				ObjectMeta:    metav1.ObjectMeta{Namespace: oldestPod.Namespace, Name: oldestPod.Name},
				DeleteOptions: nil,
			},
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// these are lifted from k/k: https://github.com/kubernetes/kubernetes/blob/release-1.23/pkg/api/v1/pod/util.go#L286

// IsPodAvailable returns true if a pod is available; false otherwise.
// Precondition for an available pod is that it must be ready. On top
// of that, there are two cases when a pod can be considered available:
// 1. minReadySeconds == 0, or
// 2. LastTransitionTime (is set) + minReadySeconds < current time
func isPodAvailable(pod *v1.Pod, minReadySeconds int32, now metav1.Time) bool {
	if !isPodReady(pod) {
		return false
	}

	c := getPodReadyCondition(pod.Status)
	minReadySecondsDuration := time.Duration(minReadySeconds) * time.Second
	if minReadySeconds == 0 || (!c.LastTransitionTime.IsZero() && c.LastTransitionTime.Add(minReadySecondsDuration).Before(now.Time)) {
		return true
	}

	return false
}

func isPodReady(pod *v1.Pod) bool {
	return isPodReadyConditionTrue(pod.Status)
}

func isPodReadyConditionTrue(status v1.PodStatus) bool {
	condition := getPodReadyCondition(status)
	return condition != nil && condition.Status == v1.ConditionTrue
}

func getPodReadyCondition(status v1.PodStatus) *v1.PodCondition {
	_, condition := getPodCondition(&status, v1.PodReady)
	return condition
}

func getPodCondition(status *v1.PodStatus, conditionType v1.PodConditionType) (int, *v1.PodCondition) {
	if status == nil {
		return -1, nil
	}
	return getPodConditionFromList(status.Conditions, conditionType)
}

func getPodConditionFromList(conditions []v1.PodCondition, conditionType v1.PodConditionType) (int, *v1.PodCondition) {
	if conditions == nil {
		return -1, nil
	}
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return i, &conditions[i]
		}
	}
	return -1, nil
}
