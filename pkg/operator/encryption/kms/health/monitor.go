package health

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

type Monitor struct {
	probe        *Probe
	writer       *OperatorConditionWriter
	observerPod  string
	interval     time.Duration
	writeTimeout time.Duration
}

func NewMonitor(
	probe *Probe,
	writer *OperatorConditionWriter,
	observerPod string,
	interval, writeTimeout time.Duration,
) *Monitor {
	return &Monitor{
		probe:        probe,
		writer:       writer,
		observerPod:  observerPod,
		interval:     interval,
		writeTimeout: writeTimeout,
	}
}

// Run blocks until ctx is cancelled. wait.UntilWithContext recovers panics
// inside tick so a misbehaving plugin or apiserver flake cannot crash the
// sidecar.
func (m *Monitor) Run(ctx context.Context) {
	wait.UntilWithContext(ctx, m.tick, m.interval)
}

func (m *Monitor) tick(ctx context.Context) {
	status := m.probe.Probe(ctx)
	status.ObserverPod = m.observerPod

	writeCtx, cancel := context.WithTimeout(ctx, m.writeTimeout)
	defer cancel()
	if err := m.writer.Write(writeCtx, status); err != nil {
		klog.ErrorS(err, "kms-health: writer failed; continuing")
	}
}
