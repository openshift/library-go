package health

import (
	"context"
	"time"

	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

type Prober interface {
	Probe(ctx context.Context) HealthStatus
}

// Monitor never exits on probe or write failures; the next tick is the
// retry, and ctx cancellation is the only exit path. Skipped writes
// (apiserver Forbidden, NotFound, transient network failure) leave the
// published status one tick stale, up to one healthyInterval; the next
// tick republishes.
type Monitor struct {
	probe             Prober
	writer            StatusWriter
	observerPod       string
	healthyInterval   time.Duration
	unhealthyInterval time.Duration
	// writeTimeout bounds each writer.Write call so apiserver slowness
	// cannot stall the probe loop. probeTimeout + writeTimeout stack
	// per tick. Keep their sum below unhealthyInterval, otherwise a
	// stuck Write delays the next tick past the unhealthy cadence and
	// the "tighten on unhealthy" mechanism collapses. Must be > 0.
	writeTimeout time.Duration
	clock        clock.Clock
}

func NewMonitor(
	prober Prober,
	writer StatusWriter,
	observerPod string,
	healthyInterval, unhealthyInterval, writeTimeout time.Duration,
) *Monitor {
	return &Monitor{
		probe:             prober,
		writer:            writer,
		observerPod:       observerPod,
		healthyInterval:   healthyInterval,
		unhealthyInterval: unhealthyInterval,
		writeTimeout:      writeTimeout,
		clock:             clock.RealClock{},
	}
}

// Run blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	for {
		status := m.probe.Probe(ctx)
		status.ObserverPod = m.observerPod

		// Cancel inline rather than via defer: defers in unbounded loops
		// accumulate until the function returns.
		writeCtx, writeCancel := context.WithTimeout(ctx, m.writeTimeout)
		err := m.writer.Write(writeCtx, status)
		writeCancel()
		if err != nil {
			klog.ErrorS(err, "kms-health: writer failed; continuing")
		}

		interval := m.healthyInterval
		if !status.Healthz.IsOK() {
			interval = m.unhealthyInterval
		}

		select {
		case <-ctx.Done():
			return
		case <-m.clock.After(interval):
		}
	}
}
