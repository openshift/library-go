package latencyprofilecontroller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	listerv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	// set of reasons used for updating status
	reasonLatencyProfileUpdated          = "ProfileUpdated"
	reasonLatencyProfileUpdateTriggered  = "ProfileUpdateTriggered"
	reasonLatencyProfileEmpty            = "ProfileEmpty"
	reasonLatencyProfileUpdateProhibited = "ProfileUpdateProhibited"

	// different status types
	workerLatencyProfileProgressing = "WorkerLatencyProfileProgressing"
	workerLatencyProfileComplete    = "WorkerLatencyProfileComplete"
)

type MatchProfileRevisionConfigsFunc func(profile configv1.WorkerLatencyProfileType, revisions []int32) (match bool, revisionsHaveSyncedMessage string, err error)
type CheckProfileRejectionFunc func(
	desiredProfile configv1.WorkerLatencyProfileType,
	currentRevisions []int32,
) (isRejected bool, rejectMsg string, err error)

// LatencyProfileController either instantly via the informers
// or periodically via resync, lists the config/v1/node object
// and fetches the worker latency profile applied on the cluster which is used to
// updates the status of respective operator resource that uses this controller.
// The current state of the operand is by watching the configs applied
// to different static pod revisions that are active and uses the information to
// update status as either progressing or completed or degraded.
// Note: In case new latency profiles are added in the future in openshift/api
// this could break cluster upgrades and set this controller into degraded state
// because of an "unknown latency profile" error.
type LatencyProfileController struct {
	operatorClient          v1helpers.StaticPodOperatorClient
	targetNamespace         string
	configNodeLister        listerv1.NodeLister
	checkProfileRejectionFn CheckProfileRejectionFunc
	matchRevisionsFn        MatchProfileRevisionConfigsFunc
}

func NewLatencyProfileController(
	operatorClient v1helpers.StaticPodOperatorClient,
	targetNamespace string,
	checkProfileRejectionFn CheckProfileRejectionFunc,
	matchRevisionsFn MatchProfileRevisionConfigsFunc,
	nodeInformer configv1informers.NodeInformer,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	eventRecorder events.Recorder,
) factory.Controller {

	ret := &LatencyProfileController{
		operatorClient:          operatorClient,
		targetNamespace:         targetNamespace,
		checkProfileRejectionFn: checkProfileRejectionFn,
		matchRevisionsFn:        matchRevisionsFn,
		configNodeLister:        nodeInformer.Lister(),
	}

	return factory.New().WithInformers(
		// this is for our general configuration input and our status output in case another actor changes it
		operatorClient.Informer(),

		// We use nodeInformer for observing current worker latency profile
		nodeInformer.Informer(),

		// for configmaps of operator client target namespace
		kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().ConfigMaps().Informer(),
	).ResyncEvery(time.Minute).WithSync(ret.sync).WithSyncDegradedOnError(operatorClient).ToController(
		"WorkerLatencyProfile",
		eventRecorder.WithComponentSuffix("latency-profile-controller"),
	)
}

func (c *LatencyProfileController) sync(ctx context.Context, syncCtx factory.SyncContext) error {

	// Collect the current latency profile
	configNodeObj, err := c.configNodeLister.Get("cluster")

	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}

		// in case config/v1/node/cluster object doesn't exist
		_, err = c.updateStatus(
			ctx,
			false, true, // not progressing, complete=True
			reasonLatencyProfileEmpty,
			"nodes.config.openshift.io/cluster object was not found on the cluster",
		)
		return err
	}

	_, operatorStatus, _, err := c.operatorClient.GetStaticPodOperatorState()
	if err != nil {
		return err
	}

	// Collect the unique set of revisions for all nodes in cluster
	revisionMap := make(map[int32]bool)
	uniqueRevisions := []int32{}
	for _, nodeStatus := range operatorStatus.NodeStatuses {
		revision := nodeStatus.CurrentRevision
		if !revisionMap[revision] {
			revisionMap[revision] = true
			uniqueRevisions = append(uniqueRevisions, revision)
		}
	}

	// In case a checkProfileRejection func was used, status will be updated accordingly
	// ("" profile is also default profile, so "" -> anotherProfile: rejection can be handled)
	if c.checkProfileRejectionFn != nil {
		isRejected, rejectMsg, err := c.checkProfileRejectionFn(configNodeObj.Spec.WorkerLatencyProfile, uniqueRevisions)
		if err != nil {
			return err
		}
		// if profile transition is rejected, set status to progress=False, complete=False
		// and degrade operator with suitable error message
		if isRejected {
			_, err = c.updateStatus(
				ctx,
				false, false, // not progressing, not complete
				reasonLatencyProfileUpdateProhibited,
				"",
			)
			if err != nil {
				return err
			}
			return fmt.Errorf(rejectMsg)
		}
	}

	// in case profile was not rejected and,
	// in case of empty workerlatency profile, set status Complete=False and pre-empt sync;
	// Note: There's a very low amount of risk involved with this, we might end up skipping a
	// Progress status when user tries to go from Medium -> "", but that's the only risk.
	// Apart from that at all times we could ideally expect the profile value to be empty only
	// for clusters that do not use the worker latency profile feature at all,
	// also since this is a non-GA feature having a no-op case with profile empty would make sense.
	// TODO: we should change this behavior in the future before Worker Latency Profiles feature is GA.
	if configNodeObj.Spec.WorkerLatencyProfile == "" {
		_, err = c.updateStatus(
			ctx,
			false, true, // not progressing, complete=True
			reasonLatencyProfileEmpty,
			"latency profile not set on cluster",
		)
		return err
	}

	// For each revision, check that the configmap for that revision have correct arg val pairs or not
	revisionsHaveSynced, syncMsg, err := c.matchRevisionsFn(configNodeObj.Spec.WorkerLatencyProfile, uniqueRevisions)
	if err != nil {
		return err
	}

	if revisionsHaveSynced {
		_, err = c.updateStatus(
			ctx,
			false, true, // not progressing, complete=True
			reasonLatencyProfileUpdated,
			syncMsg,
		)
	} else {
		_, err = c.updateStatus(
			ctx,
			true, false, // progressing=True, not complete
			reasonLatencyProfileUpdateTriggered,
			syncMsg,
		)
	}
	return err
}

func (c *LatencyProfileController) updateStatus(ctx context.Context, isProgressing, isComplete bool, reason, message string) (bool, error) {
	progressingCondition := operatorv1.OperatorCondition{
		Type:   workerLatencyProfileProgressing,
		Status: operatorv1.ConditionFalse,
		Reason: reason,
	}
	completedCondition := operatorv1.OperatorCondition{
		Type:   workerLatencyProfileComplete,
		Status: operatorv1.ConditionFalse,
		Reason: reason,
	}

	if isProgressing {
		progressingCondition.Status = operatorv1.ConditionTrue
		progressingCondition.Message = message
	} else if isComplete {
		completedCondition.Status = operatorv1.ConditionTrue
		completedCondition.Message = message
	}

	_, isUpdated, err := v1helpers.UpdateStatus(
		ctx, c.operatorClient,
		v1helpers.UpdateConditionFn(progressingCondition),
		v1helpers.UpdateConditionFn(completedCondition),
	)
	return isUpdated, err
}
