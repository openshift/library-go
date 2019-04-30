package availability

import (
	"fmt"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corelisterv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const availabilityControllerWorkQueueKey = "key"

// AvailabilityController watches for new master nodes and continuously monitor the availability on these nodes for configured component.
type AvailabilityController struct {
	operatorClient v1helpers.StaticPodOperatorClient

	nodeLister corelisterv1.NodeLister

	monitor *monitorController

	cachesToSync  []cache.InformerSynced
	queue         workqueue.RateLimitingInterface
	eventRecorder events.Recorder
}

type AvailabilityMonitorFunc func(node v1.Node) error

// NewAvailabilityController creates a new availability controller.
func NewAvailabilityController(
	operatorClient v1helpers.StaticPodOperatorClient,
	kubeInformersClusterScoped informers.SharedInformerFactory,
	eventRecorder events.Recorder,
	monitors []*Monitor,
) *AvailabilityController {
	c := &AvailabilityController{
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder.WithComponentSuffix("availability-controller"),
		nodeLister:     kubeInformersClusterScoped.Core().V1().Nodes().Lister(),
		monitor:        newMonitorController(monitors),

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "AvailabilityController"),
	}

	kubeInformersClusterScoped.Core().V1().Nodes().Informer().AddEventHandler(c.eventHandler())

	c.cachesToSync = append(c.cachesToSync, operatorClient.Informer().HasSynced)
	c.cachesToSync = append(c.cachesToSync, kubeInformersClusterScoped.Core().V1().Nodes().Informer().HasSynced)

	return c
}

// NewAvailabilityMonitor return monitor that will periodically execute the health check on given node.
// The node object contain .Addresses that can be used to target the probes.
// When the healthCheck return error, it is reported as warning event (and should be moved to degraded condition).
func NewAvailabilityMonitor(name string, healthCheck func(node *v1.Node) error) *Monitor {
	return &Monitor{
		Name:            name,
		HealthCheckFunc: healthCheck,
		status:          []*monitorStatus{},
	}
}

// Monitor specify a named health check performed on all nodes.
type Monitor struct {
	Name            string
	HealthCheckFunc func(node *v1.Node) error

	status []*monitorStatus
	sync.Mutex
}

// Failing return map of nodes that failed the last health check.
func (m Monitor) Failing() map[string]error {
	m.Lock()
	defer m.Unlock()
	result := map[string]error{}

	for _, status := range m.status {
		if status.isFailing() {
			result[status.nodeName] = status.lastObservedError
		}
	}
	return result
}

// getStatus return the current status for single node.
func (m *Monitor) getStatus(nodeName string) *monitorStatus {
	m.Lock()
	defer m.Unlock()
	for i, status := range m.status {
		if status.nodeName == nodeName {
			return m.status[i]
		}
	}
	return nil
}

// pruneNodes prunes status for nodes that are no longer observed
func (m *Monitor) pruneNodes(observedNodes []*v1.Node) {
	m.Lock()
	defer m.Unlock()
	newStatus := []*monitorStatus{}
	for _, n := range observedNodes {
		for i := range m.status {
			if m.status[i].nodeName == n.Name {
				continue
			}
			newStatus = append(newStatus, m.status[i])
		}
	}
	m.status = newStatus
}

// updateStatus sets the status for the given node.
func (m *Monitor) updateStatus(nodeName string, status *monitorStatus) {
	m.Lock()
	defer m.Unlock()

	foundNode := false
	for i, n := range m.status {
		if n.nodeName != nodeName {
			continue
		}
		foundNode = true
		m.status[i] = status
	}

	if !foundNode {
		m.status = append(m.status, status)
	}
}

// monitorStatus tracks the internal state of single monitor.
type monitorStatus struct {
	name                  string
	nodeName              string
	lastCheckTime         time.Time
	lastObservedErrorTime time.Time
	lastObservedError     error

	sync.RWMutex
}

// isFailing return true if the last performed check failed.
func (s *monitorStatus) isFailing() bool {
	s.RLock()
	defer s.RUnlock()
	return s.lastCheckTime == s.lastObservedErrorTime
}

type monitorController struct {
	monitors []Monitor
	nodes    []*v1.Node

	resultCh chan monitorStatus
	sync.RWMutex
}

func newMonitorController(monitors []Monitor) *monitorController {
	statusChan := make(chan monitorStatus)
	m := &monitorController{
		resultCh: statusChan,
		monitors: monitors,
	}
	return m
}

// setNodes updates the nodes the controller track state for
func (c *monitorController) setNodes(nodes []*v1.Node) {
	c.Lock()
	defer c.Unlock()
	c.nodes = nodes
}

// getNodes return list of currently tracked nodes
func (c *monitorController) getNodes() []*v1.Node {
	c.RLock()
	defer c.RUnlock()
	return c.nodes
}

// getMonitors return list of monitors that perform check on nodes
func (c *monitorController) getMonitors() []Monitor {
	c.RLock()
	defer c.RUnlock()
	return c.monitors
}

func (c *monitorController) Run(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		// Start each monitor in parallel and wait for the result
		var wg sync.WaitGroup
		for _, m := range c.getMonitors() {
			wg.Add(1)

			go func(monitor Monitor) {
				defer func() {
					if r := recover(); r != nil {
						klog.Warningf("availability monitor recovered from panic: %v", r)
					}
					wg.Done()
				}()

				monitorCheck := monitor.HealthCheckFunc

				// Prune nodes that were removed
				m.pruneNodes(c.getNodes())

				// Perform defined check on each node
				var nodeWg sync.WaitGroup
				for _, node := range c.getNodes() {
					nodeWg.Add(1)

					// Perform check on single node
					go func(checkFn func(checkNode *v1.Node) error) {
						defer wg.Done()

						currentStatus := m.getStatus(node.Name)
						if currentStatus == nil {
							currentStatus = &monitorStatus{}
						}
						err := checkFn(node)

						// Update current node status
						timestamp := time.Now().UTC()
						currentStatus.nodeName = node.Name
						currentStatus.lastCheckTime = timestamp
						if err != nil {
							currentStatus.lastObservedError = err
							currentStatus.lastObservedErrorTime = timestamp
						}
						klog.V(4).Infof("Node %q monitor %q reporting: %s", node.Name, monitor.Name, spew.Sdump(currentStatus))
					}(monitorCheck)
				}

			}(m)
		}

		wg.Wait()
	}
}

// Run starts the kube-apiserver and blocks until stopCh is closed.
func (c *AvailabilityController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting AvailabilityController")
	defer klog.Infof("Shutting down AvailabilityController")
	if !cache.WaitForCacheSync(stopCh, c.cachesToSync...) {
		return
	}

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, stopCh)

	// start the monitor
	go c.monitor.Run(stopCh)

	// observe the monitor state
	go func() {
		if err := c.observeMonitorState(stopCh); err != nil {
			panic(fmt.Sprintf("observing monitor state failed: %v", err))
		}
	}()

	<-stopCh
}

func (c *AvailabilityController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *AvailabilityController) observeMonitorState(stopCh <-chan struct{}) error {
	err := wait.PollImmediateUntil(5*time.Second, func() (bool, error) {
		for _, monitor := range c.monitor.getMonitors() {
			failingNodes := monitor.Failing()
			if len(failingNodes) == 0 {
				return false, nil
			}

			// TODO: This should be degraded condition
			for nodeName, err := range failingNodes {
				c.eventRecorder.Warningf("ServiceAvailabilityChanged", "Node %q monitor %q reporting error: %v", nodeName, monitor.Name, err)
			}
		}
		return false, nil
	}, stopCh)

	return err
}

func (c *AvailabilityController) sync() error {
	selector, err := labels.NewRequirement("node-role.kubernetes.io/master", selection.Equals, []string{""})
	if err != nil {
		panic(err)
	}

	observedNodes, err := c.nodeLister.List(labels.NewSelector().Add(*selector))
	if err != nil {
		return err
	}

	c.monitor.setNodes(observedNodes)

	return nil
}

func (c *AvailabilityController) processNextWorkItem() bool {
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
func (c *AvailabilityController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(availabilityControllerWorkQueueKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(availabilityControllerWorkQueueKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(availabilityControllerWorkQueueKey) },
	}
}
