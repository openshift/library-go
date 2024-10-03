package metrics

import (
	"k8s.io/component-base/metrics"
)

const (
	namespace = "installer_controller"
	subsystem = "static_pod"
)

type Metrics struct {
	staticPodRolloutDuration *metrics.HistogramVec
}

func New() *Metrics {
	return &Metrics{
		staticPodRolloutDuration: metrics.NewHistogramVec(
			&metrics.HistogramOpts{
				Namespace:      namespace,
				Subsystem:      subsystem,
				Name:           "rollout_duration",
				Help:           "Duration of static pod rollouts broken down by pod name in seconds.",
				Buckets:        []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192},
				StabilityLevel: metrics.ALPHA,
			},
			[]string{"pod"},
		),
	}
}

func (m *Metrics) Register(registrationFunc func(metrics.Registerable) error) error {
	return registrationFunc(m.staticPodRolloutDuration)
}

func (m *Metrics) ObserveStaticPodRollout(pod string, duration float64) {
	m.staticPodRolloutDuration.WithLabelValues(pod).Observe(duration)
}
