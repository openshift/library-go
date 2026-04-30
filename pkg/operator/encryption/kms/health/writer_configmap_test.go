package health

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	testNamespace = "kms-health-test"
	testCMName    = "kms-health-status"
)

func newTestConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testCMName,
			Namespace: testNamespace,
		},
	}
}

// decodeEntry parses data.<class> back into a classEntry. Comparing
// decoded structs avoids brittleness against JSON field ordering changes.
func decodeEntry(t *testing.T, raw string) classEntry {
	t.Helper()
	var e classEntry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatalf("decode classEntry %q: %v", raw, err)
	}
	return e
}

func TestConfigMapWriter_writesHealthyEntryUnderOKKey(t *testing.T) {
	client := fake.NewClientset(newTestConfigMap())
	w := NewConfigMapWriter(client, testNamespace, testCMName)

	status := HealthStatus{
		Healthz:     Healthz{Class: HealthClassOK},
		KeyIDHash:   "abc123",
		Timestamp:   time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC),
		ObserverPod: "mock-kmsv2-provider-node",
	}
	if err := w.Write(context.Background(), status); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := client.CoreV1().ConfigMaps(testNamespace).
		Get(context.Background(), testCMName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	raw, ok := got.Data[string(HealthClassOK)]
	if !ok {
		t.Fatalf("data[%q] missing; data=%v", HealthClassOK, got.Data)
	}
	entry := decodeEntry(t, raw)

	want := classEntry{
		Timestamp:   "2026-04-24T12:00:00Z",
		ObserverPod: "mock-kmsv2-provider-node",
		KeyIDHash:   "abc123",
	}
	if entry != want {
		t.Errorf("data[ok]: got %+v, want %+v", entry, want)
	}

	// Other class keys must be absent: we never observed them.
	for _, c := range []HealthClass{HealthClassNotOK, HealthClassRPCError} {
		if _, present := got.Data[string(c)]; present {
			t.Errorf("data[%q] present after only an OK probe; data=%v", c, got.Data)
		}
	}
}

func TestConfigMapWriter_writesUnhealthyEntryUnderNotOKKey(t *testing.T) {
	client := fake.NewClientset(newTestConfigMap())
	w := NewConfigMapWriter(client, testNamespace, testCMName)

	status := HealthStatus{
		Healthz:     Healthz{Class: HealthClassNotOK, Detail: "boom"},
		Timestamp:   time.Date(2026, 4, 24, 12, 1, 0, 0, time.UTC),
		ObserverPod: "p",
	}
	if err := w.Write(context.Background(), status); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, _ := client.CoreV1().ConfigMaps(testNamespace).
		Get(context.Background(), testCMName, metav1.GetOptions{})
	raw, ok := got.Data[string(HealthClassNotOK)]
	if !ok {
		t.Fatalf("data[%q] missing; data=%v", HealthClassNotOK, got.Data)
	}
	entry := decodeEntry(t, raw)

	want := classEntry{
		Timestamp:   "2026-04-24T12:01:00Z",
		ObserverPod: "p",
		Detail:      "boom",
	}
	if entry != want {
		t.Errorf("data[not-ok]: got %+v, want %+v", entry, want)
	}
}

func TestConfigMapWriter_writesRPCErrorEntryUnderRPCErrorKey(t *testing.T) {
	client := fake.NewClientset(newTestConfigMap())
	w := NewConfigMapWriter(client, testNamespace, testCMName)

	status := HealthStatus{
		Healthz:     Healthz{Class: HealthClassRPCError, Detail: "Unavailable"},
		Timestamp:   time.Date(2026, 4, 24, 12, 2, 0, 0, time.UTC),
		ObserverPod: "p",
	}
	if err := w.Write(context.Background(), status); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, _ := client.CoreV1().ConfigMaps(testNamespace).
		Get(context.Background(), testCMName, metav1.GetOptions{})
	raw, ok := got.Data[string(HealthClassRPCError)]
	if !ok {
		t.Fatalf("data[%q] missing; data=%v", HealthClassRPCError, got.Data)
	}
	entry := decodeEntry(t, raw)

	want := classEntry{
		Timestamp:   "2026-04-24T12:02:00Z",
		ObserverPod: "p",
		Detail:      "Unavailable",
	}
	if entry != want {
		t.Errorf("data[rpc-error]: got %+v, want %+v", entry, want)
	}
}

// TestConfigMapWriter_tickPreservesOtherClasses is the load-bearing
// test for the schema's whole point: a probe of class X must not
// clobber data.Y / data.Z. If a future refactor swaps merge-patch for
// Update or for a strategic-merge-with-replace directive, this test
// goes red.
func TestConfigMapWriter_tickPreservesOtherClasses(t *testing.T) {
	// Pre-populate data.ok with a stale healthy entry; tick rpc-error;
	// assert data.ok survived byte-for-byte.
	staleOK := `{"timestamp":"2026-04-24T11:00:00Z","observerPod":"p","keyIDHash":"old"}`
	existing := newTestConfigMap()
	existing.Data = map[string]string{
		string(HealthClassOK): staleOK,
	}
	client := fake.NewClientset(existing)
	w := NewConfigMapWriter(client, testNamespace, testCMName)

	status := HealthStatus{
		Healthz:     Healthz{Class: HealthClassRPCError, Detail: "Unavailable"},
		Timestamp:   time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC),
		ObserverPod: "p",
	}
	if err := w.Write(context.Background(), status); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, _ := client.CoreV1().ConfigMaps(testNamespace).
		Get(context.Background(), testCMName, metav1.GetOptions{})

	if got.Data[string(HealthClassOK)] != staleOK {
		t.Errorf("data[ok] mutated by rpc-error tick: got %q, want %q",
			got.Data[string(HealthClassOK)], staleOK)
	}
	if _, ok := got.Data[string(HealthClassRPCError)]; !ok {
		t.Errorf("data[rpc-error] not written; data=%v", got.Data)
	}
}

func TestConfigMapWriter_patchPreservesUnrelatedKeys(t *testing.T) {
	// Same load-bearing property as tickPreservesOtherClasses, but for
	// keys outside our schema entirely (e.g. an annotation-style key set
	// by something else in the same CM).
	existing := newTestConfigMap()
	existing.Data = map[string]string{
		"unrelated-key": "set-by-something-else",
	}
	client := fake.NewClientset(existing)
	w := NewConfigMapWriter(client, testNamespace, testCMName)

	if err := w.Write(context.Background(), HealthStatus{
		Healthz:     Healthz{Class: HealthClassOK},
		Timestamp:   time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC),
		ObserverPod: "p",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, _ := client.CoreV1().ConfigMaps(testNamespace).
		Get(context.Background(), testCMName, metav1.GetOptions{})
	if got.Data["unrelated-key"] != "set-by-something-else" {
		t.Errorf("merge patch dropped unrelated key: got %q", got.Data["unrelated-key"])
	}
	if _, ok := got.Data[string(HealthClassOK)]; !ok {
		t.Errorf("data[ok] not written; data=%v", got.Data)
	}
}

func TestConfigMapWriter_createsConfigMapWhenMissing(t *testing.T) {
	// Empty clientset, no ConfigMap to patch. Write self-heals by
	// creating the CM seeded with this tick's class entry; subsequent
	// ticks would extend it via merge-patch.
	client := fake.NewClientset()
	w := NewConfigMapWriter(client, testNamespace, testCMName)

	status := HealthStatus{
		Healthz:     Healthz{Class: HealthClassOK},
		KeyIDHash:   "abc",
		Timestamp:   time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC),
		ObserverPod: "p",
	}
	if err := w.Write(context.Background(), status); err != nil {
		t.Fatalf("Write on missing CM: %v", err)
	}

	got, err := client.CoreV1().ConfigMaps(testNamespace).
		Get(context.Background(), testCMName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	raw, ok := got.Data[string(HealthClassOK)]
	if !ok {
		t.Fatalf("data[%q] missing after create; data=%v", HealthClassOK, got.Data)
	}
	want := classEntry{
		Timestamp:   "2026-04-24T12:00:00Z",
		ObserverPod: "p",
		KeyIDHash:   "abc",
	}
	if entry := decodeEntry(t, raw); entry != want {
		t.Errorf("data[ok]: got %+v, want %+v", entry, want)
	}
}
