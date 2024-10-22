package status

import (
	"context"
	"fmt"
	applyconfigv1 "github.com/openshift/client-go/config/applyconfigurations/config/v1"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"strings"
	"time"

	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	configv1helpers "github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

type VersionGetter interface {
	// SetVersion is a way to set the version for an operand.  It must be thread-safe
	SetVersion(operandName, version string)
	// GetVersion is way to get the versions for all operands.  It must be thread-safe and return an object that doesn't mutate
	GetVersions() map[string]string
	// VersionChangedChannel is a channel that will get an item whenever SetVersion has been called
	VersionChangedChannel() <-chan struct{}
}

type RelatedObjectsFunc func() (isset bool, objs []configv1.ObjectReference)

type StatusSyncer struct {
	controllerInstanceName string
	clusterOperatorName    string
	relatedObjects         []configv1.ObjectReference
	relatedObjectsFunc     RelatedObjectsFunc
	clock                  clock.PassiveClock

	versionGetter         VersionGetter
	operatorClient        operatorv1helpers.OperatorClient
	clusterOperatorClient configv1client.ClusterOperatorsGetter
	clusterOperatorLister configv1listers.ClusterOperatorLister

	controllerFactory *factory.Factory
	recorder          events.Recorder
	degradedInertia   Inertia

	removeUnusedVersions bool
}

var _ factory.Controller = &StatusSyncer{}

func (c *StatusSyncer) Name() string {
	return c.clusterOperatorName
}

func NewClusterOperatorStatusController(
	name string,
	relatedObjects []configv1.ObjectReference,
	clusterOperatorClient configv1client.ClusterOperatorsGetter,
	clusterOperatorInformer configv1informers.ClusterOperatorInformer,
	operatorClient operatorv1helpers.OperatorClient,
	versionGetter VersionGetter,
	recorder events.Recorder,
	clock clock.PassiveClock,
) *StatusSyncer {
	instanceName := name
	return &StatusSyncer{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "ClusterOperatorStatus"),
		clusterOperatorName:    name,
		relatedObjects:         relatedObjects,
		clock:                  clock,
		versionGetter:          versionGetter,
		clusterOperatorClient:  clusterOperatorClient,
		clusterOperatorLister:  clusterOperatorInformer.Lister(),
		operatorClient:         operatorClient,
		degradedInertia:        MustNewInertia(2 * time.Minute).Inertia,
		controllerFactory: factory.New().ResyncEvery(time.Minute).WithInformers(
			operatorClient.Informer(),
			clusterOperatorInformer.Informer(),
		),
		recorder: recorder.WithComponentSuffix("status-controller"),
	}
}

// WithRelatedObjectsFunc allows the set of related objects to be dynamically
// determined.
//
// The function returns (isset, objects)
//
// If isset is false, then the set of related objects is copied over from the
// existing ClusterOperator object. This is useful in cases where an operator
// has just restarted, and hasn't yet reconciled.
//
// Any statically-defined related objects (in NewClusterOperatorStatusController)
// will always be included in the result.
func (c *StatusSyncer) WithRelatedObjectsFunc(f RelatedObjectsFunc) {
	c.relatedObjectsFunc = f
}

func (c *StatusSyncer) Run(ctx context.Context, workers int) {
	c.controllerFactory.
		WithPostStartHooks(c.watchVersionGetterPostRunHook).
		WithSync(c.Sync).
		ToController(
			c.controllerInstanceName,
			c.recorder,
		).
		Run(ctx, workers)
}

// WithDegradedInertia returns a copy of the StatusSyncer with the
// requested inertia function for degraded conditions.
func (c *StatusSyncer) WithDegradedInertia(inertia Inertia) *StatusSyncer {
	output := *c
	output.degradedInertia = inertia
	return &output
}

// WithVersionRemoval returns a copy of the StatusSyncer that will
// remove versions that are missing in VersionGetter from the status.
func (c *StatusSyncer) WithVersionRemoval() *StatusSyncer {
	output := *c
	output.removeUnusedVersions = true
	return &output
}

// sync reacts to a change in prereqs by finding information that is required to match another value in the cluster. This
// must be information that is logically "owned" by another component.
func (c StatusSyncer) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	detailedSpec, currentDetailedStatus, _, err := c.operatorClient.GetOperatorState()
	if apierrors.IsNotFound(err) {
		syncCtx.Recorder().Warningf("StatusNotFound", "Unable to determine current operator status for clusteroperator/%s", c.clusterOperatorName)
		if err := c.clusterOperatorClient.ClusterOperators().Delete(ctx, c.clusterOperatorName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}

	originalClusterOperatorObj, err := c.clusterOperatorLister.Get(c.clusterOperatorName)
	if err != nil && !apierrors.IsNotFound(err) {
		syncCtx.Recorder().Warningf("StatusFailed", "Unable to get current operator status for clusteroperator/%s: %v", c.clusterOperatorName, err)
		return err
	}

	// ensure that we have a clusteroperator resource
	if originalClusterOperatorObj == nil || apierrors.IsNotFound(err) {
		klog.Infof("clusteroperator/%s not found", c.clusterOperatorName)
		var createErr error
		_, createErr = c.clusterOperatorClient.ClusterOperators().Apply(ctx, applyconfigv1.ClusterOperator(c.clusterOperatorName), metav1.ApplyOptions{FieldManager: c.controllerInstanceName})
		if apierrors.IsNotFound(createErr) {
			// this means that the API isn't present.  We did not fail.  Try again later
			klog.Infof("ClusterOperator API not created")
			syncCtx.Queue().AddRateLimited(factory.DefaultQueueKey)
			return nil
		}
		if createErr != nil {
			syncCtx.Recorder().Warningf("StatusCreateFailed", "Failed to create operator status: %v", createErr)
			return createErr
		}
		// it's ok to create and then ApplyStatus with different content because Appy and ApplyStatus are tracked as different fieldManagers in metadata
		// re-enter the loop
		return nil
	}

	previouslyDesiredStatus, err := applyconfigv1.ExtractClusterOperatorStatus(originalClusterOperatorObj, c.controllerInstanceName)
	if err != nil && !apierrors.IsNotFound(err) {
		syncCtx.Recorder().Warningf("StatusFailed", "Unable to get extract operator status for clusteroperator/%s: %v", c.clusterOperatorName, err)
		return err
	}

	if detailedSpec.ManagementState == operatorv1.Unmanaged && !management.IsOperatorAlwaysManaged() {
		desiredStatus := applyconfigv1.ClusterOperatorStatus()
		desiredStatus.WithConditions(
			applyconfigv1.ClusterOperatorStatusCondition().
				WithType(configv1.OperatorAvailable).
				WithStatus(configv1.ConditionUnknown).
				WithReason("Unmanaged"),
			applyconfigv1.ClusterOperatorStatusCondition().
				WithType(configv1.OperatorProgressing).
				WithStatus(configv1.ConditionUnknown).
				WithReason("Unmanaged"),
			applyconfigv1.ClusterOperatorStatusCondition().
				WithType(configv1.OperatorDegraded).
				WithStatus(configv1.ConditionUnknown).
				WithReason("Unmanaged"),
			applyconfigv1.ClusterOperatorStatusCondition().
				WithType(configv1.OperatorUpgradeable).
				WithStatus(configv1.ConditionUnknown).
				WithReason("Unmanaged"),
			applyconfigv1.ClusterOperatorStatusCondition().
				WithType(configv1.EvaluationConditionsDetected).
				WithStatus(configv1.ConditionUnknown).
				WithReason("Unmanaged"),
		)
		operatorv1helpers.SetClusterOperatorApplyConditionsLastTransitionTime(c.clock, &desiredStatus.Conditions, previouslyDesiredStatus.Status.Conditions)

		if equivalent, err := operatorv1helpers.AreClusterOperatorStatusEquivalent(desiredStatus, previouslyDesiredStatus.Status); err != nil {
			return fmt.Errorf("unable to compare desired and existing: %w", err)
		} else if equivalent {
			return nil
		}

		if _, err := c.clusterOperatorClient.ClusterOperators().ApplyStatus(ctx, applyconfigv1.ClusterOperator(c.Name()).WithStatus(desiredStatus), metav1.ApplyOptions{
			Force:        true,
			FieldManager: c.controllerInstanceName,
		}); err != nil {
			return err
		}

		if !skipOperatorStatusChangedEvent(previouslyDesiredStatus.Status, desiredStatus) {
			syncCtx.Recorder().Eventf("OperatorStatusChanged", "Status for operator %s changed: %s", c.clusterOperatorName, configv1helpers.GetStatusDiff(previouslyDesiredStatus.Status, desiredStatus))
		}
		return nil
	}

	desiredStatus := applyconfigv1.ClusterOperatorStatus()
	if c.relatedObjectsFunc != nil {
		isSet, ro := c.relatedObjectsFunc()

		newRelatedObjects := []*applyconfigv1.ObjectReferenceApplyConfiguration{}
		if !isSet { // temporarily unknown - copy over from existing object
			if previouslyDesiredStatus.Status != nil {
				for i := range previouslyDesiredStatus.Status.RelatedObjects {
					newRelatedObjects = append(newRelatedObjects, &previouslyDesiredStatus.Status.RelatedObjects[i])
				}
			}
		} else {
			for _, obj := range ro {
				newRelatedObjects = append(newRelatedObjects, operatorv1helpers.ToApplyClusterOperatorRelatedObj(obj))
			}
		}

		// merge in any static objects
		for _, obj := range c.relatedObjects {
			applyObj := operatorv1helpers.ToApplyClusterOperatorRelatedObj(obj)
			found := false
			for _, existingObj := range newRelatedObjects {
				if applyObj == existingObj {
					found = true
					break
				}
			}
			if !found {
				newRelatedObjects = append(newRelatedObjects, applyObj)
			}
		}
		desiredStatus.WithRelatedObjects(newRelatedObjects...)
	} else {
		for _, obj := range c.relatedObjects {
			desiredStatus.WithRelatedObjects(operatorv1helpers.ToApplyClusterOperatorRelatedObj(obj))
		}
	}

	desiredStatus.WithConditions(
		UnionClusterCondition(configv1.OperatorDegraded, operatorv1.ConditionFalse, c.degradedInertia, currentDetailedStatus.Conditions...),
		UnionClusterCondition(configv1.OperatorProgressing, operatorv1.ConditionFalse, nil, currentDetailedStatus.Conditions...),
		UnionClusterCondition(configv1.OperatorAvailable, operatorv1.ConditionTrue, nil, currentDetailedStatus.Conditions...),
		UnionClusterCondition(configv1.OperatorUpgradeable, operatorv1.ConditionTrue, nil, currentDetailedStatus.Conditions...),
		UnionClusterCondition(configv1.EvaluationConditionsDetected, operatorv1.ConditionFalse, nil, currentDetailedStatus.Conditions...),
	)

	desiredStatus.WithVersions(c.createNewOperatorVersions(previouslyDesiredStatus.Status, syncCtx)...)

	// if we have no diff, just return
	if equivalent, err := operatorv1helpers.AreClusterOperatorStatusEquivalent(desiredStatus, previouslyDesiredStatus.Status); err != nil {
		return fmt.Errorf("unable to compare desired and existing: %w", err)
	} else if equivalent {
		return nil
	}

	if klog.V(2).Enabled() {
		previousClusterOperator := &configv1.ClusterOperator{}
		if previouslyDesiredStatus != nil {
			s, _ := operatorv1helpers.ToClusterOperator(previouslyDesiredStatus.Status)
			if s != nil {
				previousClusterOperator.Status = *s
			}
		}
		desiredClusterOperator := &configv1.ClusterOperator{}
		s, _ := operatorv1helpers.ToClusterOperator(desiredStatus)
		desiredClusterOperator.Status = *s

		klog.V(2).Infof("clusteroperator/%s diff %v", c.clusterOperatorName, resourceapply.JSONPatchNoError(previousClusterOperator, desiredClusterOperator))
	}

	if _, updateErr := c.clusterOperatorClient.ClusterOperators().ApplyStatus(ctx, applyconfigv1.ClusterOperator(c.Name()).WithStatus(desiredStatus), metav1.ApplyOptions{
		Force:        true,
		FieldManager: c.controllerInstanceName,
	}); updateErr != nil {
		return updateErr
	}
	if !skipOperatorStatusChangedEvent(previouslyDesiredStatus.Status, desiredStatus) {
		syncCtx.Recorder().Eventf("OperatorStatusChanged", "Status for clusteroperator/%s changed: %s", c.clusterOperatorName, configv1helpers.GetStatusDiff(previouslyDesiredStatus.Status, desiredStatus))
	}
	return nil
}

func skipOperatorStatusChangedEvent(originalStatus, newStatus *applyconfigv1.ClusterOperatorStatusApplyConfiguration) bool {
	originalWithScrubbedConditions := originalStatus
	if originalStatus != nil {
		originalWithScrubbedConditions = &applyconfigv1.ClusterOperatorStatusApplyConfiguration{
			Conditions:     nil,
			Versions:       originalStatus.Versions,
			RelatedObjects: originalStatus.RelatedObjects,
			Extension:      originalStatus.Extension,
		}

		for _, curr := range originalStatus.Conditions {
			switch ptr.Deref(curr.Type, "") {
			case configv1.OperatorAvailable, configv1.OperatorDegraded, configv1.OperatorProgressing, configv1.OperatorUpgradeable:
				scrubbedCondition := &applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration{
					Type:               curr.Type,
					Status:             curr.Status,
					LastTransitionTime: curr.LastTransitionTime,
					Reason:             curr.Reason,
					Message:            ptr.To(strings.TrimPrefix(ptr.Deref(curr.Message, ""), "\ufeff")),
				}
				originalWithScrubbedConditions.WithConditions(scrubbedCondition)
			default:
				originalWithScrubbedConditions.WithConditions(&curr)
			}
		}
	}
	return len(configv1helpers.GetStatusDiff(originalWithScrubbedConditions, newStatus)) == 0
}

func (c *StatusSyncer) createNewOperatorVersions(previousStatus *applyconfigv1.ClusterOperatorStatusApplyConfiguration, syncCtx factory.SyncContext) []*applyconfigv1.OperandVersionApplyConfiguration {
	ret := []*applyconfigv1.OperandVersionApplyConfiguration{}
	versions := c.versionGetter.GetVersions()
	// Add new versions from versionGetter to status
	for operand, version := range versions {
		ret = append(ret, applyconfigv1.OperandVersion().WithName(operand).WithVersion(version))

		if previousStatus != nil {
			previousVersion := operatorv1helpers.FindOperandVersion(previousStatus.Versions, operand)
			if previousVersion == nil || ptr.Deref(previousVersion.Version, "") != version {
				// having this message will give us a marker in events when the operator updated compared to when the operand is updated
				syncCtx.Recorder().Eventf("OperatorVersionChanged", "clusteroperator/%s version %q changed from %q to %q", c.clusterOperatorName, operand, previousVersion, version)
			}
		}
	}

	if c.removeUnusedVersions {
		return ret
	}

	// if we are here, we should keep all existing versions. This seems a little weird, but I don't remember the history
	if previousStatus != nil {
		for i := range previousStatus.Versions {
			previousOperandVersion := previousStatus.Versions[i]
			desiredVersion := operatorv1helpers.FindOperandVersionPtr(ret, ptr.Deref(previousOperandVersion.Name, ""))
			if desiredVersion == nil {
				ret = append(ret, &previousOperandVersion)
			}
		}
	}

	return ret
}

func (c *StatusSyncer) watchVersionGetterPostRunHook(ctx context.Context, syncCtx factory.SyncContext) error {
	defer utilruntime.HandleCrash()

	versionCh := c.versionGetter.VersionChangedChannel()
	// always kick at least once
	syncCtx.Queue().Add(factory.DefaultQueueKey)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-versionCh:
			syncCtx.Queue().Add(factory.DefaultQueueKey)
		}
	}
}
