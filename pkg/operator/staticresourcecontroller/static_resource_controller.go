package staticresourcecontroller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/operator/management"

	"k8s.io/apimachinery/pkg/util/sets"

	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"

	"github.com/openshift/library-go/pkg/operator/events"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const (
	workQueueKey = "key"
)

type StaticResourceController struct {
	name      string
	manifests resourceapply.AssetFunc
	files     []string

	operatorClient v1helpers.OperatorClient
	clients        *resourceapply.ClientHolder

	cachesToSync  []cache.InformerSynced
	queue         workqueue.RateLimitingInterface
	eventRecorder events.Recorder
}

// NewStaticResourceController returns a controller that maintains certain static manifests. Most "normal" types are supported,
// but feel free to add ones we missed.  Use .AddInformer() to provide triggering conditions.
func NewStaticResourceController(
	name string,
	manifests resourceapply.AssetFunc,
	files []string,
	clients *resourceapply.ClientHolder,
	operatorClient v1helpers.OperatorClient,
	eventRecorder events.Recorder,
) *StaticResourceController {
	c := &StaticResourceController{
		name:      name,
		manifests: manifests,
		files:     files,

		operatorClient: operatorClient,
		clients:        clients,

		eventRecorder: eventRecorder.WithComponentSuffix(strings.ToLower(name)),
		queue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), name),
	}

	c.operatorClient.Informer().AddEventHandler(c.eventHandler())

	return c
}

func (c *StaticResourceController) AddInformer(informer cache.SharedIndexInformer) *StaticResourceController {
	informer.AddEventHandler(c.eventHandler())
	c.cachesToSync = append(c.cachesToSync, informer.HasSynced)
	return c
}

func (c *StaticResourceController) AddNamespaceInformer(informer cache.SharedIndexInformer, namespaces ...string) *StaticResourceController {
	interestingNamespaces := sets.NewString(namespaces...)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ns, ok := obj.(*corev1.Namespace)
			if !ok {
				c.queue.Add(workQueueKey)
			}
			if interestingNamespaces.Has(ns.Name) {
				c.queue.Add(workQueueKey)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			ns, ok := old.(*corev1.Namespace)
			if !ok {
				c.queue.Add(workQueueKey)
			}
			if interestingNamespaces.Has(ns.Name) {
				c.queue.Add(workQueueKey)
			}
		},
		DeleteFunc: func(obj interface{}) {
			ns, ok := obj.(*corev1.Namespace)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
					return
				}
				ns, ok = tombstone.Obj.(*corev1.Namespace)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Namespace %#v", obj))
					return
				}
			}
			if interestingNamespaces.Has(ns.Name) {
				c.queue.Add(workQueueKey)
			}
		},
	})
	c.cachesToSync = append(c.cachesToSync, informer.HasSynced)

	return c
}

func (c StaticResourceController) Sync() error {
	operatorSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}
	if !management.IsOperatorManaged(operatorSpec.ManagementState) {
		return nil
	}

	errors := []error{}
	directResourceResults := resourceapply.ApplyDirectly(c.clients, c.eventRecorder, c.manifests, c.files...)
	for _, currResult := range directResourceResults {
		if currResult.Error != nil {
			errors = append(errors, fmt.Errorf("%q (%T): %v", currResult.File, currResult.Type, currResult.Error))
			continue
		}
	}

	if len(errors) > 0 {
		message := ""
		for _, err := range errors {
			message = message + err.Error() + "\n"
		}
		errors = append(errors,
			appendErrors(v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
				Type:    fmt.Sprintf("%sDegraded", c.name),
				Status:  operatorv1.ConditionTrue,
				Reason:  "SyncError",
				Message: message,
			})))...,
		)
	} else {
		errors = append(errors,
			appendErrors(v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
				Type:   fmt.Sprintf("%sDegraded", c.name),
				Status: operatorv1.ConditionFalse,
				Reason: "AsExpected",
			})))...,
		)
	}

	return utilerrors.NewAggregate(errors)
}

func appendErrors(_ *operatorv1.OperatorStatus, _ bool, err error) []error {
	if err != nil {
		return []error{err}
	}
	return []error{}
}

func (c *StaticResourceController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", c.name)
	defer klog.Infof("Shutting down %s", c.name)

	if !cache.WaitForCacheSync(ctx.Done(), c.cachesToSync...) {
		return
	}

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, ctx.Done())

	// add time based trigger
	go wait.Until(func() { c.queue.Add(workQueueKey) }, time.Minute, ctx.Done())

	<-ctx.Done()
}

func (c *StaticResourceController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *StaticResourceController) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.Sync()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}

// eventHandler queues the operator to check spec and status
func (c *StaticResourceController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(workQueueKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(workQueueKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(workQueueKey) },
	}
}
