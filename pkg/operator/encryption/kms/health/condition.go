package health

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
)

// Per-pod condition Types: KMSv2HealthPlugin_<observerPod>_Available and
// KMSv2HealthPlugin_<observerPod>_Degraded. Pod-name hyphens pass through
// verbatim; library-go UnionCondition handles them.
const (
	conditionTypePrefix          = "KMSv2HealthPlugin_"
	conditionTypeAvailableSuffix = "_Available"
	conditionTypeDegradedSuffix  = "_Degraded"

	reasonAsExpected       = "AsExpected"
	reasonPluginUnhealthy  = "PluginUnhealthy"
	reasonProbeUnreachable = "ProbeUnreachable"
	reasonHealthzNotOK     = "HealthzNotOK"
	reasonRPCError         = "RPCError"

	// fieldManagerPrefix isolates each pod's two condition entries via SSA
	// per-entry ownership (Conditions is listType=map keyed on Type).
	fieldManagerPrefix = "kms-health-monitor-"
)

type OperatorConditionWriter struct {
	client       operatorv1helpers.OperatorClient
	observerPod  string
	fieldManager string
	clock        clock.Clock
}

func NewOperatorConditionWriter(client operatorv1helpers.OperatorClient, observerPod string) *OperatorConditionWriter {
	return &OperatorConditionWriter{
		client:       client,
		observerPod:  observerPod,
		fieldManager: fieldManagerPrefix + observerPod,
		clock:        clock.RealClock{},
	}
}

type conditionDecision struct {
	status operatorv1.ConditionStatus
	reason string
}

// Asymmetric: Available expresses confirmed-good, so RPCError ("we don't
// know") maps to Unknown; Degraded expresses persistent-wrong, and an
// unreachable plugin IS wrong, so Degraded is True.
func mapHealthClass(class HealthClass) (avail, degraded conditionDecision) {
	switch class {
	case HealthClassOK:
		return conditionDecision{operatorv1.ConditionTrue, reasonAsExpected},
			conditionDecision{operatorv1.ConditionFalse, reasonAsExpected}
	case HealthClassNotOK:
		return conditionDecision{operatorv1.ConditionFalse, reasonPluginUnhealthy},
			conditionDecision{operatorv1.ConditionTrue, reasonHealthzNotOK}
	case HealthClassRPCError:
		return conditionDecision{operatorv1.ConditionUnknown, reasonProbeUnreachable},
			conditionDecision{operatorv1.ConditionTrue, reasonRPCError}
	}
	// Defensive default for an unknown class. HealthClass is a closed set,
	// so this is unreachable today, but a future class would otherwise
	// crash a sidecar.
	return conditionDecision{operatorv1.ConditionUnknown, reasonProbeUnreachable},
		conditionDecision{operatorv1.ConditionTrue, reasonRPCError}
}

func buildMessage(status HealthStatus) string {
	if status.Healthz.IsOK() {
		return "keyIDHash=" + status.KeyIDHash
	}
	if status.KeyIDHash != "" {
		return fmt.Sprintf("keyIDHash=%s detail=%s", status.KeyIDHash, status.Healthz.Detail)
	}
	return "detail=" + status.Healthz.Detail
}

// Carry over the prior LastTransitionTime when Status is unchanged so
// consumers don't see field churn on every reconcile. Mirrors
// v1helpers.SetOperatorCondition for the SSA path.
func resolveLastTransitionTime(prior []operatorv1.OperatorCondition, conditionType string, newStatus operatorv1.ConditionStatus, now time.Time) metav1.Time {
	for i := range prior {
		if prior[i].Type != conditionType {
			continue
		}
		if prior[i].Status == newStatus {
			return prior[i].LastTransitionTime
		}
		break
	}
	return metav1.NewTime(now)
}

func (w *OperatorConditionWriter) Write(ctx context.Context, status HealthStatus) error {
	availType := conditionTypePrefix + w.observerPod + conditionTypeAvailableSuffix
	degradedType := conditionTypePrefix + w.observerPod + conditionTypeDegradedSuffix

	avail, degraded := mapHealthClass(status.Healthz.Class)
	msg := buildMessage(status)

	// Read failure is non-fatal: worst case LTT=now on an unchanged Status,
	// self-correcting next tick. Skipping the publish would punish transient
	// apiserver glitches harder than the contract asks for.
	var priorConditions []operatorv1.OperatorCondition
	if _, opStatus, _, err := w.client.GetOperatorState(); err == nil && opStatus != nil {
		priorConditions = opStatus.Conditions
	}

	now := w.clock.Now()
	availLTT := resolveLastTransitionTime(priorConditions, availType, avail.status, now)
	degradedLTT := resolveLastTransitionTime(priorConditions, degradedType, degraded.status, now)

	cfg := applyoperatorv1.OperatorStatus().WithConditions(
		applyoperatorv1.OperatorCondition().
			WithType(availType).
			WithStatus(avail.status).
			WithReason(avail.reason).
			WithMessage(msg).
			WithLastTransitionTime(availLTT),
		applyoperatorv1.OperatorCondition().
			WithType(degradedType).
			WithStatus(degraded.status).
			WithReason(degraded.reason).
			WithMessage(msg).
			WithLastTransitionTime(degradedLTT),
	)

	if err := w.client.ApplyOperatorStatus(ctx, w.fieldManager, cfg); err != nil {
		return fmt.Errorf("apply operator-condition status (fieldManager=%s): %w", w.fieldManager, err)
	}
	return nil
}
