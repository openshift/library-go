package controller

import (
	"context"
	"time"

	operatorcontrolplanev1alpha1 "github.com/openshift/api/operatorcontrolplane/v1alpha1"
	operatorcontrolplaneclientv1alpha1 "github.com/openshift/client-go/operatorcontrolplane/clientset/versioned/typed/operatorcontrolplane/v1alpha1"
	operatorcontrolplaneinformersv1alpha1 "github.com/openshift/client-go/operatorcontrolplane/informers/externalversions/operatorcontrolplane/v1alpha1"
	operatorcontrolplanelistersv1alpha1 "github.com/openshift/client-go/operatorcontrolplane/listers/operatorcontrolplane/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

// PodNetworkConnectivityCheckController continuously performs network connectivity
// checks and reports the results.
type PodNetworkConnectivityCheckController interface {
	factory.Controller
}

// controller implements a PodNetworkConnectivityCheckController that discovers the list of endpoints to
// check by looking for PodNetworkConnectivityChecks in a given namespace, for a specific pod. Updates to
// the PodNetworkConnectivityCheck status are queued up and handled asynchronously such that disruptions
// to the ability to update the PodNetworkConnectivityCheck status do not disrupt the ability to perform
// the connectivity checks.
type controller struct {
	factory.Controller
	podName      string
	podNamespace string
	checksGetter operatorcontrolplaneclientv1alpha1.PodNetworkConnectivityCheckInterface
	checkLister  operatorcontrolplanelistersv1alpha1.PodNetworkConnectivityCheckNamespaceLister
	recorder     events.Recorder
	// each PodNetworkConnectivityCheck gets its own ConnectionChecker
	updaters map[string]ConnectionChecker
}

// Returns a new PodNetworkConnectivityCheckController that performs network connectivity checks
// as specified in the PodNetworkConnectivityChecks defined in the specified namespace, for the specified pod.
func NewPodNetworkConnectivityCheckController(podName, podNamespace string, checksGetter operatorcontrolplaneclientv1alpha1.PodNetworkConnectivityChecksGetter, checkInformer operatorcontrolplaneinformersv1alpha1.PodNetworkConnectivityCheckInformer, recorder events.Recorder) PodNetworkConnectivityCheckController {
	c := &controller{
		podName:      podName,
		podNamespace: podNamespace,
		checksGetter: checksGetter.PodNetworkConnectivityChecks(podNamespace),
		checkLister:  checkInformer.Lister().PodNetworkConnectivityChecks(podNamespace),
		recorder:     recorder,
		updaters:     map[string]ConnectionChecker{},
	}
	c.Controller = factory.New().
		WithSync(c.Sync).
		WithBareInformers(checkInformer.Informer()).
		ResyncEvery(1*time.Minute).
		ToController("check-endpoints", recorder)
	return c
}

// Sync ensures that the status updaters for each PodNetworkConnectivityCheck is started
// and then performs each check.
func (c *controller) Sync(ctx context.Context, syncContext factory.SyncContext) error {
	checkList, err := c.checkLister.List(labels.Everything())
	if err != nil {
		return err
	}

	// filter list of checks for current pod
	var checks []*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck
	for _, check := range checkList {
		if check.Spec.SourcePod == c.podName {
			checks = append(checks, check)
		}
	}

	// create & start status updaters if needed
	for _, check := range checks {
		if updater := c.updaters[check.Name]; updater == nil {
			c.updaters[check.Name] = NewConnectionChecker(check, c, c.recorder)
			go c.updaters[check.Name].Run(ctx)
		}
	}

	// stop & delete unneeded status updaters
	for name, updater := range c.updaters {
		var keep bool
		for _, check := range checks {
			if check.Name == name {
				keep = true
				break
			}
		}
		if !keep {
			updater.Stop()
			delete(c.updaters, name)
		}
	}

	return nil
}

// Get implements PodNetworkConnectivityCheckClient
func (c *controller) Get(name string) (*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck, error) {
	return c.checkLister.Get(name)
}

// UpdateStatus implements v1alpha1helpers.PodNetworkConnectivityCheckClient
func (c *controller) UpdateStatus(ctx context.Context, check *operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck, opts metav1.UpdateOptions) (*operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck, error) {
	return c.checksGetter.UpdateStatus(ctx, check, opts)
}
