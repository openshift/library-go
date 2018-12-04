package revision

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

type prometheusMetricsProvider struct {
	componentName string
}

func newPrometheusMetricsProvider(name string) prometheusMetricsProvider {
	return prometheusMetricsProvider{componentName: name}
}

func (p prometheusMetricsProvider) NewRevisionMetrics() *prometheus.GaugeVec {
	revisionMetrics := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Subsystem: p.componentName,
			Name:      "latestRevision",
			Help:      fmt.Sprintf("Current %s operator revision.", p.componentName),
		},
		[]string{"observedGeneration"},
	)
	if err := prometheus.Register(revisionMetrics); err != nil {
		panic(err)
	}
	return revisionMetrics
}
