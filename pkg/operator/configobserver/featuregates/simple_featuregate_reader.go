package featuregates

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"

	v1 "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type FeatureGateChangeHandlerFunc func(featureChange FeatureChange)

type FeatureGateAccess interface {
	SetChangeHandler(featureGateChangeHandlerFn FeatureGateChangeHandlerFunc)

	Run(ctx context.Context)
	InitialFeatureGatesObserved() chan struct{}
	CurrentFeatureGates() (enabled []string, disabled []string, err error)
	AreInitialFeatureGatesObserved() bool
}

type Features struct {
	Enabled  []string
	Disabled []string
}

type FeatureChange struct {
	Previous *Features
	New      Features
}

type defaultFeatureGateAccess struct {
	desiredVersion              string
	missingVersionMarker        string
	clusterVersionLister        configlistersv1.ClusterVersionLister
	featureGateLister           configlistersv1.FeatureGateLister
	initialFeatureGatesObserved chan struct{}

	featureGateChangeHandlerFn FeatureGateChangeHandlerFunc

	lock            sync.Mutex
	started         bool
	initialFeatures Features
	currentFeatures Features

	queue         workqueue.RateLimitingInterface
	eventRecorder events.Recorder
}

// NewFeatureGateAccess returns a controller that keeps the list of enabled/disabled featuregates up to date.
// desiredVersion is the version of this operator that would be set on the clusteroperator.status.versions.
// missingVersionMarker is the stub version provided by the operator.  If that is also the desired version,
// then the most either the desired clusterVersion or most recent version will be used.
// clusterVersionInformer is used when desiredVersion and missingVersionMarker are the same to derive the "best" version
// of featuregates to use.
// featureGateInformer is used to track changes to the featureGates once they are initially set.
// By default, when the enabled/disabled list  of featuregates changes, os.Exit is called.  This behavior can be
// overridden by calling SetChangeHandler to whatever you wish the behavior to be.
// A common construct is:
/* go
featureGateAccessor := NewFeatureGateAccess(args)
go featureGateAccessor.Run(ctx)

select{
case <- featureGateAccessor.InitialFeatureGatesObserved():
	enabled, disabled, _ := featureGateAccessor.CurrentFeatureGates()
	klog.Infof("FeatureGates initialized: enabled=%v  disabled=%v", enabled, disabled)
case <- time.After(1*time.Minute):
	klog.Errorf("timed out waiting for FeatureGate detection")
	return fmt.Errorf("timed out waiting for FeatureGate detection")
}

// whatever other initialization you have to do, at this point you have FeatureGates to drive your behavior.
*/
// That construct is easy.  It is better to use the .spec.observedConfiguration construct common in library-go operators
// to avoid gating your general startup on FeatureGate determination, but if you haven't already got that mechanism
// this construct is easy.
func NewFeatureGateAccess(
	desiredVersion, missingVersionMarker string,
	clusterVersionInformer v1.ClusterVersionInformer,
	featureGateInformer v1.FeatureGateInformer,
	eventRecorder events.Recorder) FeatureGateAccess {
	c := &defaultFeatureGateAccess{
		desiredVersion:              desiredVersion,
		missingVersionMarker:        missingVersionMarker,
		clusterVersionLister:        clusterVersionInformer.Lister(),
		featureGateLister:           featureGateInformer.Lister(),
		initialFeatureGatesObserved: make(chan struct{}),
		queue:                       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "feature-gate-detector"),
		eventRecorder:               eventRecorder,
	}
	c.SetChangeHandler(ForceExit)

	// we aren't expecting many
	clusterVersionInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.queue.Add("cluster")
		},
		UpdateFunc: func(old, cur interface{}) {
			c.queue.Add("cluster")
		},
		DeleteFunc: func(uncast interface{}) {
			c.queue.Add("cluster")
		},
	})
	featureGateInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.queue.Add("cluster")
		},
		UpdateFunc: func(old, cur interface{}) {
			c.queue.Add("cluster")
		},
		DeleteFunc: func(uncast interface{}) {
			c.queue.Add("cluster")
		},
	})

	return c
}

func ForceExit(featureChange FeatureChange) {
	if featureChange.Previous != nil {
		os.Exit(0)
	}
}

func (c *defaultFeatureGateAccess) SetChangeHandler(featureGateChangeHandlerFn FeatureGateChangeHandlerFunc) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.started {
		panic("programmer error, cannot update the change handler after starting")
	}
	c.featureGateChangeHandlerFn = featureGateChangeHandlerFn
}

func (c *defaultFeatureGateAccess) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting feature-gate-detector")
	defer klog.Infof("Shutting down feature-gate-detector")

	go wait.UntilWithContext(ctx, c.runWorker, time.Second)

	<-ctx.Done()
}

func (c *defaultFeatureGateAccess) syncHandler(ctx context.Context) error {
	desiredVersion := c.desiredVersion
	if c.missingVersionMarker == c.desiredVersion {
		clusterVersion, err := c.clusterVersionLister.Get("version")
		if apierrors.IsNotFound(err) {
			return nil // we will be re-triggered when it is created
		}
		if err != nil {
			return err
		}

		desiredVersion = clusterVersion.Status.Desired.Version
		if len(desiredVersion) == 0 && len(clusterVersion.Status.History) > 0 {
			desiredVersion = clusterVersion.Status.History[0].Version
		}
	}

	featureGate, err := c.featureGateLister.Get("cluster")
	if apierrors.IsNotFound(err) {
		return nil // we will be re-triggered when it is created
	}
	if err != nil {
		return err
	}

	features := Features{}
	enabled, disabled, err := FeaturesGatesFromFeatureSets(featureGate)
	if err != nil {
		return err
	}
	features.Enabled = enabled
	features.Disabled = disabled

	c.setFeatureGates(features)

	return nil
}

func (c *defaultFeatureGateAccess) setFeatureGates(features Features) {
	c.lock.Lock()
	defer c.lock.Unlock()

	var previousFeatures *Features
	if c.AreInitialFeatureGatesObserved() {
		t := c.currentFeatures
		previousFeatures = &t
	}

	c.currentFeatures = features

	if !c.AreInitialFeatureGatesObserved() {
		c.initialFeatures = features
		close(c.initialFeatureGatesObserved)
		c.eventRecorder.Eventf("FeatureGatesInitialized", "FeatureGates updated to %#v", c.currentFeatures)
	}

	if previousFeatures == nil || !reflect.DeepEqual(*previousFeatures, c.currentFeatures) {
		if previousFeatures != nil {
			c.eventRecorder.Eventf("FeatureGatesModified", "FeatureGates updated to %#v", c.currentFeatures)
		}

		c.featureGateChangeHandlerFn(FeatureChange{
			Previous: previousFeatures,
			New:      c.currentFeatures,
		})
	}
}

func (c *defaultFeatureGateAccess) InitialFeatureGatesObserved() chan struct{} {
	return c.initialFeatureGatesObserved
}

func (c *defaultFeatureGateAccess) AreInitialFeatureGatesObserved() bool {
	select {
	case <-c.InitialFeatureGatesObserved():
		return true
	default:
		return false
	}
}

func (c *defaultFeatureGateAccess) CurrentFeatureGates() ([]string, []string, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.AreInitialFeatureGatesObserved() {
		return nil, nil, fmt.Errorf("featureGates not yet observed")
	}
	retEnabled := make([]string, len(c.currentFeatures.Enabled))
	retDisabled := make([]string, len(c.currentFeatures.Disabled))
	copy(retEnabled, c.currentFeatures.Enabled)
	copy(retDisabled, c.currentFeatures.Disabled)

	return retEnabled, retDisabled, nil
}

func (c *defaultFeatureGateAccess) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *defaultFeatureGateAccess) processNextWorkItem(ctx context.Context) bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.syncHandler(ctx)
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}
