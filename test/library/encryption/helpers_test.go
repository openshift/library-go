package encryption

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// recordingTB intercepts failure methods so we can check Failed()
// without actually failing the real test.
type recordingTB struct {
	*testing.T
	failed atomic.Bool
}

func (r *recordingTB) Errorf(format string, args ...interface{}) {
	r.failed.Store(true)
	r.T.Logf("recorded error: "+format, args...)
}

func (r *recordingTB) FailNow() {
	r.failed.Store(true)
	runtime.Goexit()
}

func (r *recordingTB) Failed() bool { return r.failed.Load() }

func countCompletions(steps []testStep, completed *atomic.Int32) []testStep {
	wrapped := make([]testStep, len(steps))
	for i, s := range steps {
		wrapped[i] = testStep{name: s.name, testFunc: wrapWithCounter(s.testFunc, completed)}
	}
	return wrapped
}

func wrapWithCounter(fn func(testing.TB), completed *atomic.Int32) func(testing.TB) {
	return func(t testing.TB) {
		fn(t)
		completed.Add(1)
	}
}

func TestInParallel(t *testing.T) {
	noop := func(t testing.TB) {}

	tests := []struct {
		name            string
		steps           []testStep
		expectName      string
		expectFailed    bool
		expectCompleted int32
	}{
		{
			name:            "single step passes through",
			steps:           []testStep{{name: "only", testFunc: noop}},
			expectName:      "only",
			expectCompleted: 1,
		},
		{
			name: "all succeed",
			steps: []testStep{
				{name: "a", testFunc: noop},
				{name: "b", testFunc: noop},
			},
			expectName:      "a | b",
			expectCompleted: 2,
		},
		{
			name: "panic fails test and other steps complete",
			steps: []testStep{
				{name: "ok-1", testFunc: noop},
				{name: "panicker", testFunc: func(t testing.TB) { panic("boom") }},
				{name: "ok-2", testFunc: noop},
			},
			expectName:      "ok-1 | panicker | ok-2",
			expectFailed:    true,
			expectCompleted: 2,
		},
		{
			name: "FailNow fails test and other steps complete",
			steps: []testStep{
				{name: "ok", testFunc: noop},
				{name: "failnow", testFunc: func(t testing.TB) { t.FailNow() }},
			},
			expectName:      "ok | failnow",
			expectFailed:    true,
			expectCompleted: 1,
		},
		{
			name: "Errorf fails test and other steps complete",
			steps: []testStep{
				{name: "ok", testFunc: noop},
				{name: "errorer", testFunc: func(t testing.TB) { t.Errorf("broke") }},
			},
			expectName:      "ok | errorer",
			expectFailed:    true,
			expectCompleted: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var completed atomic.Int32
			rec := &recordingTB{T: t}
			combined := inParallel(countCompletions(tt.steps, &completed)...)
			combined.testFunc(rec)

			if combined.name != tt.expectName {
				t.Errorf("expected name %q, actual %q", tt.expectName, combined.name)
			}
			if rec.Failed() != tt.expectFailed {
				t.Errorf("expected Failed()=%v, actual %v", tt.expectFailed, rec.Failed())
			}
			if actual := completed.Load(); actual != tt.expectCompleted {
				t.Errorf("expected %d completed, actual %d", tt.expectCompleted, actual)
			}
		})
	}
}

func TestInParallelRunsConcurrently(t *testing.T) {
	sleep := func(t testing.TB) { time.Sleep(500 * time.Millisecond) }

	start := time.Now()
	inParallel(
		testStep{name: "a", testFunc: sleep},
		testStep{name: "b", testFunc: sleep},
		testStep{name: "c", testFunc: sleep},
	).testFunc(t)
	elapsed := time.Since(start)

	if elapsed >= 1*time.Second {
		t.Errorf("expected ~500ms (parallel), actual %v (sequential would be ~1.5s)", elapsed)
	}
}
