package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	operatorv1 "github.com/openshift/api/operator/v1"
)

func addStatusConditionsMetrics(c *Collector) {
	c.register(
		"conditions",
		"Tracks operator conditions",
		prometheus.GaugeValue,
		[]string{"condition", "status"},
		func(spec *operatorv1.OperatorSpec, status *operatorv1.OperatorStatus, staticPodStatus *operatorv1.StaticPodOperatorStatus) ([]metricValue, error) {
			// We either get static pod status or operator status here
			var conditions []operatorv1.OperatorCondition
			if status != nil {
				conditions = status.Conditions
			}
			if staticPodStatus != nil {
				conditions = staticPodStatus.Conditions
			}
			values := []metricValue{}
			for _, c := range conditions {
				values = append(values, metricValue{value: 1, labels: []string{c.Type, string(c.Status)}})
			}
			return values, nil
		})
	c.register(
		"version",
		"Tracks operator version for given observed generation",
		prometheus.GaugeValue,
		[]string{"observed_generation", "version"},
		func(spec *operatorv1.OperatorSpec, status *operatorv1.OperatorStatus, staticPodStatus *operatorv1.StaticPodOperatorStatus) ([]metricValue, error) {
			values := []metricValue{}
			if status != nil {
				values = append(values, metricValue{value: 1, labels: []string{fmt.Sprintf("%d", status.ObservedGeneration), status.Version}})
			}
			if staticPodStatus != nil {
				values = append(values, metricValue{value: 1, labels: []string{fmt.Sprintf("%d", status.ObservedGeneration), status.Version}})
			}
			return values, nil
		})
}

func addStaticPodStatusLatestRevisionMetrics(c *Collector) {
	c.register(
		"static_pod_latest_revision",
		"Tracks static pod operator latest revision",
		prometheus.GaugeValue,
		[]string{},
		func(spec *operatorv1.OperatorSpec, _ *operatorv1.OperatorStatus, status *operatorv1.StaticPodOperatorStatus) ([]metricValue, error) {
			if status == nil {
				return nil, nil
			}
			return []metricValue{{value: float64(status.LatestAvailableRevision)}}, nil
		})
}

func addStaticPodNodesMetrics(c *Collector) {
	c.register(
		"static_pod_node_current_revision",
		"Tracks the current node revision",
		prometheus.GaugeValue,
		[]string{"name"},
		func(spec *operatorv1.OperatorSpec, _ *operatorv1.OperatorStatus, status *operatorv1.StaticPodOperatorStatus) ([]metricValue, error) {
			if status == nil {
				return nil, nil
			}
			values := []metricValue{}
			for _, s := range status.NodeStatuses {
				values = append(values, metricValue{
					value:  float64(s.CurrentRevision),
					labels: []string{s.NodeName},
				})
			}
			return values, nil
		})
	c.register(
		"static_pod_node_last_failed_revision",
		"Tracks the current node last failed revision",
		prometheus.GaugeValue,
		[]string{"name"},
		func(spec *operatorv1.OperatorSpec, _ *operatorv1.OperatorStatus, status *operatorv1.StaticPodOperatorStatus) ([]metricValue, error) {
			if status == nil {
				return nil, nil
			}
			values := []metricValue{}
			for _, s := range status.NodeStatuses {
				values = append(values, metricValue{
					value:  float64(s.LastFailedRevision),
					labels: []string{s.NodeName},
				})
			}
			return values, nil
		})
	c.register(
		"static_pod_node_target_revision",
		"Tracks the current node last target revision",
		prometheus.GaugeValue,
		[]string{"name"},
		func(spec *operatorv1.OperatorSpec, _ *operatorv1.OperatorStatus, status *operatorv1.StaticPodOperatorStatus) ([]metricValue, error) {
			if status == nil {
				return nil, nil
			}
			values := []metricValue{}
			for _, s := range status.NodeStatuses {
				values = append(values, metricValue{
					value:  float64(s.TargetRevision),
					labels: []string{s.NodeName},
				})
			}
			return values, nil
		})
}
