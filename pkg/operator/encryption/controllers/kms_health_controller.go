package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	kmsHealthReportsProgressingCondition = "KmsHealthReportsProgressing"
	kmsHealthReportsDegradedCondition    = "KmsHealthReportsDegraded"
	kmsHealthReportsDegradedTimeout      = time.Hour

	healthReportsNotConvergedReason = "HealthReportsNotConverged"
)

// kmsHealthController keeps KMSEncryptionStatus.HealthReports usable for remote-key
// convergence and surfaces prolonged non-convergence on the operator:
//
//   - Periodically drops reports whose LastCheckedTime is older than
//     health.DefaultReportPruneTTL (abandoned / replaced reporters).
//   - Sets KmsHealthReportsProgressing while any KeyID group among remaining
//     reports is not unanimous on RemoteKeyID (see health.AllKeyIDsConverged).
//   - Escalates to KmsHealthReportsDegraded after Progressing has stayed True for
//     kmsHealthReportsDegradedTimeout, using Progressing.LastTransitionTime as the clock.
type kmsHealthController struct {
	controllerInstanceName   string
	operatorClient           operatorv1helpers.OperatorClient
	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled
	encryptionStatusProvider kms.EncryptionStatusProvider
	clock                    clock.PassiveClock
}

func NewKmsHealthController(
	instanceName string,
	provider Provider,
	preconditionsFulfilledFn preconditionsFulfilled,
	operatorClient operatorv1helpers.OperatorClient,
	encryptionStatusProvider kms.EncryptionStatusProvider,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &kmsHealthController{
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "KmsHealth"),
		operatorClient:           operatorClient,
		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
		encryptionStatusProvider: encryptionStatusProvider,
		clock:                    clock.RealClock{},
	}

	return factory.New().
		WithSync(c.sync).
		WithControllerInstanceName(c.controllerInstanceName).
		ResyncEvery(time.Minute).
		WithInformers(operatorClient.Informer()).
		ToController(c.controllerInstanceName, eventRecorder.WithComponentSuffix("kms-health-controller"))
}

func (c *kmsHealthController) sync(ctx context.Context, syncCtx factory.SyncContext) (err error) {
	progressing := applyoperatorv1.OperatorCondition().
		WithType(kmsHealthReportsProgressingCondition).
		WithStatus(operatorv1.ConditionFalse)
	degraded := applyoperatorv1.OperatorCondition().
		WithType(kmsHealthReportsDegradedCondition).
		WithStatus(operatorv1.ConditionFalse)

	defer func() {
		// Do not publish False (or any update) on reconcile errors: that would clear an
		// existing Progressing/Degraded and reset the one-hour LastTransitionTime clock.
		if err != nil || progressing == nil || degraded == nil {
			return
		}
		status := applyoperatorv1.OperatorStatus().WithConditions(progressing, degraded)
		if applyErr := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); applyErr != nil {
			err = applyErr
		}
	}()

	if ready, runErr := shouldRunEncryptionController(c.operatorClient, c.preconditionsFulfilledFn, c.provider.ShouldRunEncryptionControllers); runErr != nil || !ready {
		if runErr != nil {
			progressing = nil
			degraded = nil
		}
		return runErr
	}

	encryptionStatus, err := c.encryptionStatusProvider.GetKMSEncryptionStatus(ctx)
	if err != nil {
		return err
	}
	if encryptionStatus == nil {
		return nil
	}

	now := c.clock.Now()
	pruned := health.PruneStaleReports(encryptionStatus.HealthReports, now, health.DefaultReportPruneTTL)
	if len(pruned) != len(encryptionStatus.HealthReports) {
		// Prune inside the callback so conflict retries re-read status and do not
		// overwrite HealthReports concurrently published by health reporters via SSA.
		if err := c.encryptionStatusProvider.UpdateKMSEncryptionStatus(ctx, func(s *operatorv1.KMSEncryptionStatus) {
			pruned = health.PruneStaleReports(s.HealthReports, now, health.DefaultReportPruneTTL)
			s.HealthReports = pruned
		}); err != nil {
			return fmt.Errorf("failed to prune stale KMS health reports: %w", err)
		}
	}

	if health.AllKeyIDsConverged(pruned) {
		return nil
	}

	reportPerNode := make([]string, 0, len(pruned))
	for _, report := range pruned {
		reportPerNode = append(reportPerNode, fmt.Sprintf("%s/%s=%q", report.NodeName, report.KeyID, report.RemoteKeyID))
	}

	message := fmt.Sprintf("KMS health reports have not yet converged: %s", strings.Join(reportPerNode, ", "))

	progressing = progressing.
		WithStatus(operatorv1.ConditionTrue).
		WithReason(healthReportsNotConvergedReason).
		WithMessage(message)

	_, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}
	// ApplyOperatorStatus preserves LastTransitionTime while Status is unchanged, so
	// Progressing.LastTransitionTime is the first time we observed non-convergence.
	// Degrade only after that stamp is at least kmsHealthReportsDegradedTimeout old
	// (hysteresis for rollouts / slow SKUs). On first observation existing is nil or
	// not True yet — wait for a later sync once LTT has been recorded.
	existing := operatorv1helpers.FindOperatorCondition(operatorStatus.Conditions, kmsHealthReportsProgressingCondition)
	if existing != nil && existing.Status == operatorv1.ConditionTrue && !now.Before(existing.LastTransitionTime.Add(kmsHealthReportsDegradedTimeout)) {
		degraded = degraded.
			WithStatus(operatorv1.ConditionTrue).
			WithReason(healthReportsNotConvergedReason).
			WithMessage(message)
	}

	return nil
}
