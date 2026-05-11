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

// recordingOperatorClient is a focused test double for OperatorConditionWriter:
// it captures every ApplyOperatorStatus call AND merges the applied conditions
// (LastTransitionTime included) into an in-memory OperatorStatus that
// subsequent GetOperatorState reads return. v1helpers.fakeOperatorClient drops
// LastTransitionTime in its merge, which would defeat the LTT tests.
//
// Merge semantics mirror real SSA per-entry ownership: each apply upserts its
// own conditions by Type, leaving conditions written by other fieldManagers
// untouched.
type recordingOperatorClient struct {
	status  operatorv1.OperatorStatus
	applies []recordedApply
}

type recordedApply struct {
	fieldManager string
	cfg          *applyoperatorv1.OperatorStatusApplyConfiguration
}

func newRecordingOperatorClient() *recordingOperatorClient {
	return &recordingOperatorClient{}
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

// Methods OperatorConditionWriter never calls. Panic-on-call signals if a
// future change accidentally introduces a dependency.
func (c *recordingOperatorClient) Informer() cache.SharedIndexInformer { return nil }
func (c *recordingOperatorClient) GetObjectMeta() (*metav1.ObjectMeta, error) {
	return &metav1.ObjectMeta{}, nil
}
func (c *recordingOperatorClient) GetOperatorStateWithQuorum(ctx context.Context) (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	return c.GetOperatorState()
}
func (c *recordingOperatorClient) UpdateOperatorSpec(context.Context, string, *operatorv1.OperatorSpec) (*operatorv1.OperatorSpec, string, error) {
	panic("UpdateOperatorSpec not used by OperatorConditionWriter")
}
func (c *recordingOperatorClient) UpdateOperatorStatus(context.Context, string, *operatorv1.OperatorStatus) (*operatorv1.OperatorStatus, error) {
	panic("UpdateOperatorStatus not used by OperatorConditionWriter")
}
func (c *recordingOperatorClient) ApplyOperatorSpec(context.Context, string, *applyoperatorv1.OperatorSpecApplyConfiguration) error {
	panic("ApplyOperatorSpec not used by OperatorConditionWriter")
}
func (c *recordingOperatorClient) PatchOperatorStatus(context.Context, *jsonpatch.PatchSet) error {
	panic("PatchOperatorStatus not used by OperatorConditionWriter")
}

func findCondition(conds []operatorv1.OperatorCondition, t string) *operatorv1.OperatorCondition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

// newTestWriter builds an OperatorConditionWriter with an injected fake clock
// so LTT-sensitive tests can advance time deterministically.
func newTestWriter(client *recordingOperatorClient, observerPod string, fc *clocktesting.FakeClock) *OperatorConditionWriter {
	w := NewOperatorConditionWriter(client, observerPod)
	w.clock = fc
	return w
}

func TestOperatorConditionWriter_healthyStatusWritesAvailableTrueAndDegradedFalse(t *testing.T) {
	client := newRecordingOperatorClient()
	fc := clocktesting.NewFakeClock(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	w := newTestWriter(client, testObserverPod, fc)

	err := w.Write(context.Background(), HealthStatus{
		Healthz:     Healthz{Class: HealthClassOK},
		KeyIDHash:   "abc123",
		ObserverPod: testObserverPod,
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	a := findCondition(client.status.Conditions, testTypeAvailable)
	if a == nil {
		t.Fatalf("Available condition missing; conditions=%v", client.status.Conditions)
	}
	if a.Status != operatorv1.ConditionTrue {
		t.Errorf("Available.Status: got %q, want True", a.Status)
	}
	if a.Reason != reasonAsExpected {
		t.Errorf("Available.Reason: got %q, want %q", a.Reason, reasonAsExpected)
	}
	if got, want := a.Message, "keyIDHash=abc123"; got != want {
		t.Errorf("Available.Message: got %q, want %q", got, want)
	}

	d := findCondition(client.status.Conditions, testTypeDegraded)
	if d == nil {
		t.Fatalf("Degraded condition missing; conditions=%v", client.status.Conditions)
	}
	if d.Status != operatorv1.ConditionFalse {
		t.Errorf("Degraded.Status: got %q, want False", d.Status)
	}
	if d.Reason != reasonAsExpected {
		t.Errorf("Degraded.Reason: got %q, want %q", d.Reason, reasonAsExpected)
	}
	if got, want := d.Message, "keyIDHash=abc123"; got != want {
		t.Errorf("Degraded.Message: got %q, want %q", got, want)
	}

	if got, want := len(client.applies), 1; got != want {
		t.Fatalf("apply call count: got %d, want %d", got, want)
	}
	if got, want := client.applies[0].fieldManager, testFieldManager; got != want {
		t.Errorf("fieldManager: got %q, want %q", got, want)
	}
}

func TestOperatorConditionWriter_notOKStatusWritesAvailableFalseAndDegradedTrue(t *testing.T) {
	client := newRecordingOperatorClient()
	fc := clocktesting.NewFakeClock(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	w := newTestWriter(client, testObserverPod, fc)

	err := w.Write(context.Background(), HealthStatus{
		Healthz:     Healthz{Class: HealthClassNotOK, Detail: "kid lookup failed"},
		KeyIDHash:   "deadbeef",
		ObserverPod: testObserverPod,
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	a := findCondition(client.status.Conditions, testTypeAvailable)
	if a == nil {
		t.Fatalf("Available missing")
	}
	if a.Status != operatorv1.ConditionFalse {
		t.Errorf("Available.Status: got %q, want False", a.Status)
	}
	if a.Reason != reasonPluginUnhealthy {
		t.Errorf("Available.Reason: got %q, want %q", a.Reason, reasonPluginUnhealthy)
	}
	want := "keyIDHash=deadbeef detail=kid lookup failed"
	if a.Message != want {
		t.Errorf("Available.Message: got %q, want %q", a.Message, want)
	}

	d := findCondition(client.status.Conditions, testTypeDegraded)
	if d == nil {
		t.Fatalf("Degraded missing")
	}
	if d.Status != operatorv1.ConditionTrue {
		t.Errorf("Degraded.Status: got %q, want True", d.Status)
	}
	if d.Reason != reasonHealthzNotOK {
		t.Errorf("Degraded.Reason: got %q, want %q", d.Reason, reasonHealthzNotOK)
	}
	if d.Message != want {
		t.Errorf("Degraded.Message: got %q, want %q", d.Message, want)
	}
}

func TestOperatorConditionWriter_rpcErrorStatusWritesAvailableUnknownAndDegradedTrue(t *testing.T) {
	client := newRecordingOperatorClient()
	fc := clocktesting.NewFakeClock(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	w := newTestWriter(client, testObserverPod, fc)

	err := w.Write(context.Background(), HealthStatus{
		Healthz:     Healthz{Class: HealthClassRPCError, Detail: "Unavailable"},
		ObserverPod: testObserverPod,
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	a := findCondition(client.status.Conditions, testTypeAvailable)
	if a == nil {
		t.Fatalf("Available missing")
	}
	// Asymmetric: Available expresses confirmed-good. Lost contact is not
	// "confirmed bad", so Unknown is the honest answer.
	if a.Status != operatorv1.ConditionUnknown {
		t.Errorf("Available.Status: got %q, want Unknown", a.Status)
	}
	if a.Reason != reasonProbeUnreachable {
		t.Errorf("Available.Reason: got %q, want %q", a.Reason, reasonProbeUnreachable)
	}
	if got, want := a.Message, "detail=Unavailable"; got != want {
		t.Errorf("Available.Message: got %q, want %q (no keyIDHash= prefix when KeyIDHash is empty)", got, want)
	}

	d := findCondition(client.status.Conditions, testTypeDegraded)
	if d == nil {
		t.Fatalf("Degraded missing")
	}
	// Asymmetric: Degraded expresses persistent-wrong. Inability to reach
	// the plugin IS wrong, so Degraded is True.
	if d.Status != operatorv1.ConditionTrue {
		t.Errorf("Degraded.Status: got %q, want True", d.Status)
	}
	if d.Reason != reasonRPCError {
		t.Errorf("Degraded.Reason: got %q, want %q", d.Reason, reasonRPCError)
	}
	if got, want := d.Message, "detail=Unavailable"; got != want {
		t.Errorf("Degraded.Message: got %q, want %q", got, want)
	}
}

// Repeated identical Write must not bump LastTransitionTime. If it did,
// every reconcile would churn the field and downstream consumers (rollout
// gates, alerts) would think transitions were happening when nothing has.
func TestOperatorConditionWriter_repeatedWriteSameStatusDoesNotBumpLastTransitionTime(t *testing.T) {
	client := newRecordingOperatorClient()
	t1 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	fc := clocktesting.NewFakeClock(t1)
	w := newTestWriter(client, testObserverPod, fc)

	healthy := HealthStatus{
		Healthz:     Healthz{Class: HealthClassOK},
		KeyIDHash:   "abc123",
		ObserverPod: testObserverPod,
	}
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
			t.Errorf("%s.LastTransitionTime: got %v, want %v (Status unchanged, must carry over)", ct, c.LastTransitionTime.Time, t1)
		}
	}
}

// Status flip must bump LastTransitionTime to the current time.
func TestOperatorConditionWriter_statusFlipBumpsLastTransitionTime(t *testing.T) {
	client := newRecordingOperatorClient()
	t1 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	fc := clocktesting.NewFakeClock(t1)
	w := newTestWriter(client, testObserverPod, fc)

	if err := w.Write(context.Background(), HealthStatus{
		Healthz:     Healthz{Class: HealthClassOK},
		KeyIDHash:   "abc",
		ObserverPod: testObserverPod,
	}); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	t2 := t1.Add(5 * time.Minute)
	fc.SetTime(t2)
	if err := w.Write(context.Background(), HealthStatus{
		Healthz:     Healthz{Class: HealthClassNotOK, Detail: "boom"},
		KeyIDHash:   "abc",
		ObserverPod: testObserverPod,
	}); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	for _, ct := range []string{testTypeAvailable, testTypeDegraded} {
		c := findCondition(client.status.Conditions, ct)
		if c == nil {
			t.Fatalf("%s missing", ct)
		}
		if !c.LastTransitionTime.Time.Equal(t2) {
			t.Errorf("%s.LastTransitionTime: got %v, want %v (advanced on Status flip)", ct, c.LastTransitionTime.Time, t2)
		}
	}
}

// Two writers with different ObserverPods write to the same CR without
// clobbering each other. This is the load-bearing property: per-pod
// fieldManager + per-entry SSA ownership keeps both pods' conditions
// coexisting in .status.conditions[].
func TestOperatorConditionWriter_twoWritersDifferentObserverPodsDoNotCollide(t *testing.T) {
	client := newRecordingOperatorClient()
	fc := clocktesting.NewFakeClock(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))

	const (
		podA = "kube-apiserver-master-0"
		podB = "kube-apiserver-master-1"
	)
	wa := newTestWriter(client, podA, fc)
	wb := newTestWriter(client, podB, fc)

	if err := wa.Write(context.Background(), HealthStatus{
		Healthz:     Healthz{Class: HealthClassOK},
		KeyIDHash:   "a",
		ObserverPod: podA,
	}); err != nil {
		t.Fatalf("wa.Write: %v", err)
	}
	if err := wb.Write(context.Background(), HealthStatus{
		Healthz:     Healthz{Class: HealthClassNotOK, Detail: "bad"},
		KeyIDHash:   "b",
		ObserverPod: podB,
	}); err != nil {
		t.Fatalf("wb.Write: %v", err)
	}

	wantTypes := []string{
		"KMSv2HealthPlugin_kube-apiserver-master-0_Available",
		"KMSv2HealthPlugin_kube-apiserver-master-0_Degraded",
		"KMSv2HealthPlugin_kube-apiserver-master-1_Available",
		"KMSv2HealthPlugin_kube-apiserver-master-1_Degraded",
	}
	for _, ct := range wantTypes {
		if findCondition(client.status.Conditions, ct) == nil {
			t.Errorf("condition %q missing; conditions=%v", ct, client.status.Conditions)
		}
	}
	if got, want := len(client.status.Conditions), 4; got != want {
		t.Errorf("conditions count: got %d, want %d (no overwrites)", got, want)
	}

	// Spot-check that A's OK status survived B's apply.
	availA := findCondition(client.status.Conditions, "KMSv2HealthPlugin_kube-apiserver-master-0_Available")
	if availA == nil || availA.Status != operatorv1.ConditionTrue {
		t.Errorf("podA Available: got %v, want Status=True (writer B clobbered it)", availA)
	}
	availB := findCondition(client.status.Conditions, "KMSv2HealthPlugin_kube-apiserver-master-1_Available")
	if availB == nil || availB.Status != operatorv1.ConditionFalse {
		t.Errorf("podB Available: got %v, want Status=False (NotOK)", availB)
	}

	// Per-pod fieldManager: each writer used its own.
	if got, want := len(client.applies), 2; got != want {
		t.Fatalf("apply count: got %d, want %d", got, want)
	}
	if got, want := client.applies[0].fieldManager, "kms-health-monitor-"+podA; got != want {
		t.Errorf("apply[0].fieldManager: got %q, want %q", got, want)
	}
	if got, want := client.applies[1].fieldManager, "kms-health-monitor-"+podB; got != want {
		t.Errorf("apply[1].fieldManager: got %q, want %q", got, want)
	}
}
