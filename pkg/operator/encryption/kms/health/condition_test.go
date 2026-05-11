package health

import (
	"context"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/apiserver/jsonpatch"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"
)

const (
	testObserverPod   = "kube-apiserver-master-0"
	testFieldManager  = "kms-health-monitor-kube-apiserver-master-0"
	testTypeAvailable = "KMSv2HealthPlugin_kube-apiserver-master-0_Available"
	testTypeDegraded  = "KMSv2HealthPlugin_kube-apiserver-master-0_Degraded"
)

// recordingOperatorClient merges applied conditions (LastTransitionTime
// included) into the in-memory status so GetOperatorState sees prior
// state. v1helpers.fakeOperatorClient drops LTT in its merge, which
// would defeat the LTT carry-over tests.
type recordingOperatorClient struct {
	status  operatorv1.OperatorStatus
	applies []recordedApply
}

type recordedApply struct {
	fieldManager string
	cfg          *applyoperatorv1.OperatorStatusApplyConfiguration
}

func (c *recordingOperatorClient) GetOperatorState() (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	return &operatorv1.OperatorSpec{}, c.status.DeepCopy(), "0", nil
}

func (c *recordingOperatorClient) ApplyOperatorStatus(_ context.Context, fieldManager string, cfg *applyoperatorv1.OperatorStatusApplyConfiguration) error {
	c.applies = append(c.applies, recordedApply{fieldManager: fieldManager, cfg: cfg})
	for _, ac := range cfg.Conditions {
		merged := operatorv1.OperatorCondition{}
		if ac.Type != nil {
			merged.Type = *ac.Type
		}
		if ac.Status != nil {
			merged.Status = *ac.Status
		}
		if ac.Reason != nil {
			merged.Reason = *ac.Reason
		}
		if ac.Message != nil {
			merged.Message = *ac.Message
		}
		if ac.LastTransitionTime != nil {
			merged.LastTransitionTime = *ac.LastTransitionTime
		}
		c.upsertCondition(merged)
	}
	return nil
}

func (c *recordingOperatorClient) upsertCondition(cond operatorv1.OperatorCondition) {
	for i := range c.status.Conditions {
		if c.status.Conditions[i].Type == cond.Type {
			c.status.Conditions[i] = cond
			return
		}
	}
	c.status.Conditions = append(c.status.Conditions, cond)
}

func (c *recordingOperatorClient) Informer() cache.SharedIndexInformer { return nil }
func (c *recordingOperatorClient) GetObjectMeta() (*metav1.ObjectMeta, error) {
	return &metav1.ObjectMeta{}, nil
}
func (c *recordingOperatorClient) GetOperatorStateWithQuorum(ctx context.Context) (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	return c.GetOperatorState()
}
func (c *recordingOperatorClient) UpdateOperatorSpec(context.Context, string, *operatorv1.OperatorSpec) (*operatorv1.OperatorSpec, string, error) {
	panic("not used")
}
func (c *recordingOperatorClient) UpdateOperatorStatus(context.Context, string, *operatorv1.OperatorStatus) (*operatorv1.OperatorStatus, error) {
	panic("not used")
}
func (c *recordingOperatorClient) ApplyOperatorSpec(context.Context, string, *applyoperatorv1.OperatorSpecApplyConfiguration) error {
	panic("not used")
}
func (c *recordingOperatorClient) PatchOperatorStatus(context.Context, *jsonpatch.PatchSet) error {
	panic("not used")
}

func findCondition(conds []operatorv1.OperatorCondition, t string) *operatorv1.OperatorCondition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

func newTestWriter(client *recordingOperatorClient, observerPod string, fc *clocktesting.FakeClock) *OperatorConditionWriter {
	w := NewOperatorConditionWriter(client, observerPod)
	w.clock = fc
	return w
}

func TestOperatorConditionWriter_classMapping(t *testing.T) {
	cases := []struct {
		name        string
		status      HealthStatus
		availStatus operatorv1.ConditionStatus
		availReason string
		degrStatus  operatorv1.ConditionStatus
		degrReason  string
		wantMessage string
	}{
		{
			name:        "OK",
			status:      HealthStatus{Healthz: Healthz{Class: HealthClassOK}, KeyIDHash: "abc123"},
			availStatus: operatorv1.ConditionTrue, availReason: reasonAsExpected,
			degrStatus: operatorv1.ConditionFalse, degrReason: reasonAsExpected,
			wantMessage: "keyIDHash=abc123",
		},
		{
			name:        "NotOK",
			status:      HealthStatus{Healthz: Healthz{Class: HealthClassNotOK, Detail: "kid lookup failed"}, KeyIDHash: "deadbeef"},
			availStatus: operatorv1.ConditionFalse, availReason: reasonPluginUnhealthy,
			degrStatus: operatorv1.ConditionTrue, degrReason: reasonHealthzNotOK,
			wantMessage: "keyIDHash=deadbeef detail=kid lookup failed",
		},
		{
			// Asymmetric: Available expresses confirmed-good (Unknown when we
			// don't know), Degraded expresses persistent-wrong (True since
			// unreachable IS wrong).
			name:        "RPCError",
			status:      HealthStatus{Healthz: Healthz{Class: HealthClassRPCError, Detail: "Unavailable"}},
			availStatus: operatorv1.ConditionUnknown, availReason: reasonProbeUnreachable,
			degrStatus: operatorv1.ConditionTrue, degrReason: reasonRPCError,
			wantMessage: "detail=Unavailable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &recordingOperatorClient{}
			fc := clocktesting.NewFakeClock(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
			w := newTestWriter(client, testObserverPod, fc)

			tc.status.ObserverPod = testObserverPod
			if err := w.Write(context.Background(), tc.status); err != nil {
				t.Fatalf("Write: %v", err)
			}

			a := findCondition(client.status.Conditions, testTypeAvailable)
			if a == nil {
				t.Fatalf("Available missing")
			}
			if a.Status != tc.availStatus || a.Reason != tc.availReason || a.Message != tc.wantMessage {
				t.Errorf("Available: got %+v, want status=%s reason=%s message=%q", a, tc.availStatus, tc.availReason, tc.wantMessage)
			}
			d := findCondition(client.status.Conditions, testTypeDegraded)
			if d == nil {
				t.Fatalf("Degraded missing")
			}
			if d.Status != tc.degrStatus || d.Reason != tc.degrReason || d.Message != tc.wantMessage {
				t.Errorf("Degraded: got %+v, want status=%s reason=%s message=%q", d, tc.degrStatus, tc.degrReason, tc.wantMessage)
			}
			if client.applies[0].fieldManager != testFieldManager {
				t.Errorf("fieldManager: got %q, want %q", client.applies[0].fieldManager, testFieldManager)
			}
		})
	}
}

// Status-unchanged reconciles must carry over LTT; otherwise downstream
// rollout gates and alerts would think a transition happened on every tick.
func TestOperatorConditionWriter_repeatedSameStatusCarriesOverLTT(t *testing.T) {
	client := &recordingOperatorClient{}
	t1 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	fc := clocktesting.NewFakeClock(t1)
	w := newTestWriter(client, testObserverPod, fc)

	healthy := HealthStatus{Healthz: Healthz{Class: HealthClassOK}, KeyIDHash: "abc123", ObserverPod: testObserverPod}
	if err := w.Write(context.Background(), healthy); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	fc.Step(5 * time.Minute)
	if err := w.Write(context.Background(), healthy); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	for _, ct := range []string{testTypeAvailable, testTypeDegraded} {
		c := findCondition(client.status.Conditions, ct)
		if c == nil {
			t.Fatalf("%s missing", ct)
		}
		if !c.LastTransitionTime.Time.Equal(t1) {
			t.Errorf("%s.LastTransitionTime: got %v, want %v (unchanged status must carry over)", ct, c.LastTransitionTime.Time, t1)
		}
	}
}

// Per-pod fieldManager + per-entry SSA ownership: two writers with
// different ObserverPods coexist in the same CR without clobbering.
func TestOperatorConditionWriter_twoObserverPodsCoexist(t *testing.T) {
	client := &recordingOperatorClient{}
	fc := clocktesting.NewFakeClock(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))

	const (
		podA = "kube-apiserver-master-0"
		podB = "kube-apiserver-master-1"
	)
	wa := newTestWriter(client, podA, fc)
	wb := newTestWriter(client, podB, fc)

	if err := wa.Write(context.Background(), HealthStatus{Healthz: Healthz{Class: HealthClassOK}, KeyIDHash: "a", ObserverPod: podA}); err != nil {
		t.Fatalf("wa.Write: %v", err)
	}
	if err := wb.Write(context.Background(), HealthStatus{Healthz: Healthz{Class: HealthClassNotOK, Detail: "bad"}, KeyIDHash: "b", ObserverPod: podB}); err != nil {
		t.Fatalf("wb.Write: %v", err)
	}

	if got, want := len(client.status.Conditions), 4; got != want {
		t.Errorf("conditions count: got %d, want %d", got, want)
	}
	availA := findCondition(client.status.Conditions, "KMSv2HealthPlugin_"+podA+"_Available")
	if availA == nil || availA.Status != operatorv1.ConditionTrue {
		t.Errorf("podA Available: got %v, want Status=True", availA)
	}
	availB := findCondition(client.status.Conditions, "KMSv2HealthPlugin_"+podB+"_Available")
	if availB == nil || availB.Status != operatorv1.ConditionFalse {
		t.Errorf("podB Available: got %v, want Status=False", availB)
	}
	if client.applies[0].fieldManager != "kms-health-monitor-"+podA {
		t.Errorf("apply[0].fieldManager: got %q, want kms-health-monitor-%s", client.applies[0].fieldManager, podA)
	}
	if client.applies[1].fieldManager != "kms-health-monitor-"+podB {
		t.Errorf("apply[1].fieldManager: got %q, want kms-health-monitor-%s", client.applies[1].fieldManager, podB)
	}
}
