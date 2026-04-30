package health

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	testclock "k8s.io/utils/clock/testing"
)

// recordingWriter buffers every HealthStatus it receives and lets the
// test block on each write via a channel. Bounded buffer is fine for
// unit-test scope; if a Monitor change starts writing way more than
// expected the test will deadlock — that's a useful failure.
type recordingWriter struct {
	writes chan HealthStatus
}

func newRecordingWriter() *recordingWriter {
	return &recordingWriter{writes: make(chan HealthStatus, 32)}
}

func (w *recordingWriter) Write(ctx context.Context, status HealthStatus) error {
	w.writes <- status
	return nil
}

// scriptedProber hands out pre-arranged HealthStatus values in order.
// Each Probe call consumes one. Designed to block if the Monitor asks
// for more than the test scripted — surfaces unintended extra probes.
type scriptedProber struct {
	mu      sync.Mutex
	results []HealthStatus
	calls   int
}

func (s *scriptedProber) Probe(ctx context.Context) HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls >= len(s.results) {
		// Return something sane rather than panicking mid-test; the
		// writer buffer will catch unexpected writes.
		s.calls++
		return HealthStatus{Healthz: Healthz{Class: HealthClassOK}, Timestamp: time.Now()}
	}
	r := s.results[s.calls]
	s.calls++
	return r
}

// waitForWaiters polls until the FakeClock has a registered waiter, so
// the next Step() actually triggers the Monitor's next-tick timer
// rather than being lost to the void. Bounded so misbehaving Monitors
// fail the test instead of hanging.
func waitForWaiters(t *testing.T, clk *testclock.FakeClock) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !clk.HasWaiters() {
		if time.Now().After(deadline) {
			t.Fatal("Monitor never registered a clock waiter — not scheduling next tick")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMonitor_transitionsHealthyUnhealthyHealthy(t *testing.T) {
	t0 := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	clk := testclock.NewFakeClock(t0)
	prober := &scriptedProber{
		results: []HealthStatus{
			{Healthz: Healthz{Class: HealthClassOK}, Timestamp: t0},
			{Healthz: Healthz{Class: HealthClassNotOK, Detail: "boom"}, Timestamp: t0.Add(60 * time.Second)},
			{Healthz: Healthz{Class: HealthClassOK}, Timestamp: t0.Add(70 * time.Second)},
		},
	}
	writer := newRecordingWriter()

	m := &Monitor{
		probe:             prober,
		writer:            writer,
		observerPod:       "test-pod-1",
		healthyInterval:   60 * time.Second,
		unhealthyInterval: 10 * time.Second,
		writeTimeout:      5 * time.Second,
		clock:             clk,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	// Tick 1: healthy. Probed immediately, no clock step needed first.
	got1 := <-writer.writes
	if !got1.Healthz.IsOK() {
		t.Errorf("tick 1 Healthz: got %q, want IsOK", got1.Healthz)
	}
	if got1.ObserverPod != "test-pod-1" {
		t.Errorf("tick 1 ObserverPod: got %q, want test-pod-1", got1.ObserverPod)
	}

	// Should now be waiting for healthyInterval.
	waitForWaiters(t, clk)
	clk.Step(60 * time.Second)

	// Tick 2: unhealthy. Monitor must now switch to unhealthyInterval.
	got2 := <-writer.writes
	wantTick2 := Healthz{Class: HealthClassNotOK, Detail: "boom"}
	if got2.Healthz != wantTick2 {
		t.Errorf("tick 2 Healthz: got %q, want %q", got2.Healthz, wantTick2)
	}

	// Should be waiting for unhealthyInterval (10s), not 60s. Verify by
	// stepping only 10s and seeing the next probe fire.
	waitForWaiters(t, clk)
	clk.Step(10 * time.Second)

	// Tick 3: healthy again.
	got3 := <-writer.writes
	if !got3.Healthz.IsOK() {
		t.Errorf("tick 3 Healthz: got %q, want IsOK", got3.Healthz)
	}

	cancel()
	<-done

	// Timestamps must be strictly advancing across the three recorded writes.
	if !got2.Timestamp.After(got1.Timestamp) {
		t.Errorf("timestamps not advancing: t1=%v t2=%v", got1.Timestamp, got2.Timestamp)
	}
	if !got3.Timestamp.After(got2.Timestamp) {
		t.Errorf("timestamps not advancing: t2=%v t3=%v", got2.Timestamp, got3.Timestamp)
	}
}

func TestMonitor_stopsOnContextCancel(t *testing.T) {
	t0 := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	clk := testclock.NewFakeClock(t0)
	prober := &scriptedProber{
		results: []HealthStatus{{Healthz: Healthz{Class: HealthClassOK}, Timestamp: t0}},
	}
	writer := newRecordingWriter()

	m := &Monitor{
		probe:             prober,
		writer:            writer,
		observerPod:       "p",
		healthyInterval:   60 * time.Second,
		unhealthyInterval: 10 * time.Second,
		writeTimeout:      5 * time.Second,
		clock:             clk,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	<-writer.writes // first probe happened
	waitForWaiters(t, clk)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Monitor did not stop within 2s of context cancel")
	}
}

// runMonitorCycle starts a Monitor, waits for the first write + clock
// waiter, then cancels and waits for Run to return. Shared by the leak
// test so its iteration body stays focused on the leak assertion.
func runMonitorCycle(t *testing.T) {
	t.Helper()
	t0 := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	clk := testclock.NewFakeClock(t0)
	prober := &scriptedProber{
		results: []HealthStatus{
			{Healthz: Healthz{Class: HealthClassOK}, Timestamp: t0},
		},
	}
	writer := newRecordingWriter()

	m := &Monitor{
		probe:             prober,
		writer:            writer,
		observerPod:       "p",
		healthyInterval:   60 * time.Second,
		unhealthyInterval: 10 * time.Second,
		writeTimeout:      5 * time.Second,
		clock:             clk,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	<-writer.writes
	waitForWaiters(t, clk)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Monitor did not stop within 2s of context cancel")
	}
}

// TestMonitor_noGoroutineLeak verifies Run does not leak goroutines
// after ctx cancellation. Plan §14.2 calls out goroutine leakage as a
// real-class-of-bug for the gRPC dial path; the same risk applies to
// the loop that owns the long-lived select on ctx.Done() and
// clock.After.
//
// The test runs many cycles after a warm-up snapshot. A single-shot
// check would miss per-iteration accumulation (e.g. an orphaned
// goroutine spawned inside Run that exits on the *next* tick rather
// than on ctx.Done()).
func TestMonitor_noGoroutineLeak(t *testing.T) {
	// Warm up before snapshotting: first run pulls in lazy klog buffers,
	// fake-clock test internals, etc. Snapshotting beforehand would
	// surface a one-time bump as a leak.
	runMonitorCycle(t)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	const iterations = 20
	for range iterations {
		runMonitorCycle(t)
	}

	// Cleanup is scheduler-dependent; poll up to a deadline rather than
	// using a fixed sleep that flakes on a loaded CI runner.
	runtime.GC()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		runtime.GC()
	}

	if got := runtime.NumGoroutine(); got > baseline {
		// Dump live stacks so a future regression is diagnosable from CI
		// output alone. Without this, "leaked N goroutines" gives no clue
		// to the leaking site.
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Errorf("goroutine leak after %d cycles: baseline=%d, got=%d\nstacks:\n%s",
			iterations, baseline, got, buf[:n])
	}
}
