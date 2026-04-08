package retry

import (
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
)

func TestCuttableBackOff_DelegatesToInnerBackOff(t *testing.T) {
	inner := backoff.NewConstantBackOff(5 * time.Second)
	cb := NewCuttableBackOff(inner)

	if got := cb.NextBackOff(); got != 5*time.Second {
		t.Errorf("expected 5s from delegate, got %v", got)
	}
}

func TestCuttableBackOff_CutNextByReducesInterval(t *testing.T) {
	inner := backoff.NewConstantBackOff(5 * time.Second)
	cb := NewCuttableBackOff(inner)

	cb.CutNextBy(3 * time.Second)
	if got := cb.NextBackOff(); got != 2*time.Second {
		t.Errorf("expected 2s after CutNextBy(3s), got %v", got)
	}

	// Next call without CutNextBy should return full interval.
	if got := cb.NextBackOff(); got != 5*time.Second {
		t.Errorf("expected 5s after cut consumed, got %v", got)
	}
}

func TestCuttableBackOff_CutExceedingIntervalClampedToZero(t *testing.T) {
	inner := backoff.NewConstantBackOff(2 * time.Second)
	cb := NewCuttableBackOff(inner)

	cb.CutNextBy(5 * time.Second)
	if got := cb.NextBackOff(); got != 0 {
		t.Errorf("expected 0 when cut exceeds interval, got %v", got)
	}
}

func TestCuttableBackOff_MultipleCutNextByOverwrites(t *testing.T) {
	inner := backoff.NewConstantBackOff(10 * time.Second)
	cb := NewCuttableBackOff(inner)

	cb.CutNextBy(2 * time.Second)
	cb.CutNextBy(7 * time.Second) // overwrites

	if got := cb.NextBackOff(); got != 3*time.Second {
		t.Errorf("expected 3s (10s - 7s), got %v", got)
	}
}

func TestCuttableBackOff_ResetClearsCut(t *testing.T) {
	inner := backoff.NewConstantBackOff(5 * time.Second)
	cb := NewCuttableBackOff(inner)

	cb.CutNextBy(3 * time.Second)
	cb.Reset()

	if got := cb.NextBackOff(); got != 5*time.Second {
		t.Errorf("expected delegate value after Reset cleared cut, got %v", got)
	}
}

func TestCuttableBackOff_PropagatesStop(t *testing.T) {
	cb := NewCuttableBackOff(&backoff.StopBackOff{})

	// Even with a cut pending, Stop must be returned as-is.
	cb.CutNextBy(1 * time.Second)
	if got := cb.NextBackOff(); got != backoff.Stop {
		t.Errorf("expected Stop from delegate, got %v", got)
	}
}
