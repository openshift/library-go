package staticpodcontroller

import (
	"fmt"
	"reflect"
	"time"

	"github.com/golang/glog"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corelisterv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const nodeControllerWorkQueueKey = "key"

// NodeController watches for new master nodes and adds them to the list for an operator
type NodeController struct {
	operatorConfigClient OperatorClient

	nodeListerSynced cache.InformerSynced
	nodeLister       corelisterv1.NodeLister

	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.RateLimitingInterface
}

func NewNodeController(
	operatorConfigClient OperatorClient,
	kubeInformersClusterScoped informers.SharedInformerFactory,
) *NodeController {
	c := &NodeController{
		operatorConfigClient: operatorConfigClient,
		nodeListerSynced:     kubeInformersClusterScoped.Core().V1().Nodes().Informer().HasSynced,
		nodeLister:           kubeInformersClusterScoped.Core().V1().Nodes().Lister(),

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "NodeController"),
	}

	operatorConfigClient.Informer().AddEventHandler(c.eventHandler())
	kubeInformersClusterScoped.Core().V1().Nodes().Informer().AddEventHandler(c.eventHandler())

	return c
}

func (c NodeController) sync() error {
	_, originalOperatorStatus, resourceVersion, err := c.operatorConfigClient.Get()
	if err != nil {
		return err
	}
	operatorStatus := originalOperatorStatus.DeepCopy()

	selector, err := labels.NewRequirement("node-role.kubernetes.io/master", selection.Equals, []string{""})
	if err != nil {
		panic(err)
	}
	nodes, err := c.nodeLister.List(labels.NewSelector().Add(*selector))
	if err != nil {
		return err
	}

	newTargetKubeletStates := []KubeletState{}
	// remove entries for missing nodes
	for i, kubeletState := range originalOperatorStatus.TargetKubeletStates {
		found := false
		for _, node := range nodes {
			if kubeletState.NodeName == node.Name {
				found = true
			}
		}
		if found {
			newTargetKubeletStates = append(newTargetKubeletStates, originalOperatorStatus.TargetKubeletStates[i])
		}
	}

	// add entries for new nodes
	for _, node := range nodes {
		found := false
		for _, kubeletState := range originalOperatorStatus.TargetKubeletStates {
			if kubeletState.NodeName == node.Name {
				found = true
			}
		}
		if found {
			continue
		}

		newTargetKubeletStates = append(newTargetKubeletStates, KubeletState{NodeName: node.Name})
	}
	operatorStatus.TargetKubeletStates = newTargetKubeletStates

	if !reflect.DeepEqual(originalOperatorStatus, operatorStatus) {
		_, updateError := c.operatorConfigClient.UpdateStatus(resourceVersion, operatorStatus)
		return updateError
	}

	return nil
}

// Run starts the kube-apiserver and blocks until stopCh is closed.
func (c *NodeController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	glog.Infof("Starting NodeController")
	defer glog.Infof("Shutting down NodeController")
	if !cache.WaitForCacheSync(stopCh, c.nodeListerSynced) {
		return
	}

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *NodeController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *NodeController) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.sync()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}

// eventHandler queues the operator to check spec and status
func (c *NodeController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(nodeControllerWorkQueueKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(nodeControllerWorkQueueKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(nodeControllerWorkQueueKey) },
	}
}
