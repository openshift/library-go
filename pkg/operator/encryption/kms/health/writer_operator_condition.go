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

// Condition Type prefix and suffixes. Final form per writer:
//
//	KMSv2HealthPlugin_<observerPod>_Available
//	KMSv2HealthPlugin_<observerPod>_Degraded
//
// Pod names contain hyphens (kube-apiserver-master-0); they pass through
// verbatim because library-go's UnionCondition handles hyphens correctly.
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
	// per-entry ownership (OperatorStatus.Conditions is listType=map keyed
	// on Type). Two writers with different ObserverPods cannot collide.
	fieldManagerPrefix = "kms-health-monitor-"
)

// OperatorConditionWriter publishes KMSv2 plugin health to a
// *.operator.openshift.io/cluster CRD via the OperatorClient interface, so
// the same code works for KubeAPIServer, Authentication, OpenShiftAPIServer.
//
// Two condition entries are written per call:
//
//	KMSv2HealthPlugin_<observerPod>_Available  // rolls up to ClusterOperator.Available
//	KMSv2HealthPlugin_<observerPod>_Degraded   // rolls up to ClusterOperator.Degraded
//
// LastTransitionTime: read prior conditions and carry over the existing
// timestamp when Status is unchanged, otherwise stamp now. Mirrors
// v1helpers.SetOperatorCondition (helpers.go:58-100) for the SSA path so
// consumers don't see the field churn on every reconcile.
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

// mapHealthClass implements the asymmetric mapping. Available expresses
// confirmed-good, so RPCError ("we don't know") is Unknown. Degraded
// expresses persistent-wrong, and RPCError IS wrong (we cannot reach the
// plugin), so Degraded is True.
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
	// Closed set: HealthClass values come from classifyHealthz / classifyRPCError.
	// Treat any unknown class as RPCError-equivalent rather than panicking.
	return conditionDecision{operatorv1.ConditionUnknown, reasonProbeUnreachable},
		conditionDecision{operatorv1.ConditionTrue, reasonRPCError}
}

// buildMessage renders the wire format:
//
//	healthy:                     "keyIDHash=<hex>"
//	unhealthy with KeyIDHash:    "keyIDHash=<hex> detail=<detail>"
//	unhealthy without KeyIDHash: "detail=<detail>"
func buildMessage(status HealthStatus) string {
	if status.Healthz.IsOK() {
		return "keyIDHash=" + status.KeyIDHash
	}
	if status.KeyIDHash != "" {
		return fmt.Sprintf("keyIDHash=%s detail=%s", status.KeyIDHash, status.Healthz.Detail)
	}
	return "detail=" + status.Healthz.Detail
}

// resolveLastTransitionTime mirrors v1helpers.SetOperatorCondition LTT logic
// for the SSA path: brand-new condition or Status flip stamps now;
// Status-unchanged carries over the prior LastTransitionTime so consumers
// don't see churn on every reconcile.
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

	// Read prior state for LTT carry-over. A read failure is non-fatal:
	// worst case we stamp LTT=now on a Status that didn't actually change,
	// which self-corrects on the next successful tick. Skipping the publish
	// would punish transient apiserver glitches harder than the contract
	// asks for.
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
