package observer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/api"
	prometheusv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	routev1client "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/events/eventstesting"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type fakeQueryResult struct {
	query  string
	result string
	error  error
}

type fakePrometheusClient struct {
	results      []fakeQueryResult
	queriesCount int
}

func (f fakePrometheusClient) Alerts(ctx context.Context) (v1.AlertsResult, error) {
	panic("implement me")
}

func (f fakePrometheusClient) AlertManagers(ctx context.Context) (v1.AlertManagersResult, error) {
	panic("implement me")
}

func (f fakePrometheusClient) CleanTombstones(ctx context.Context) error {
	panic("implement me")
}

func (f fakePrometheusClient) Config(ctx context.Context) (v1.ConfigResult, error) {
	panic("implement me")
}

func (f fakePrometheusClient) DeleteSeries(ctx context.Context, matches []string, startTime time.Time, endTime time.Time) error {
	panic("implement me")
}

func (f fakePrometheusClient) Flags(ctx context.Context) (v1.FlagsResult, error) {
	panic("implement me")
}

func (f fakePrometheusClient) LabelNames(ctx context.Context) ([]string, api.Warnings, error) {
	panic("implement me")
}

func (f fakePrometheusClient) LabelValues(ctx context.Context, label string) (model.LabelValues, api.Warnings, error) {
	panic("implement me")
}

func (f fakePrometheusClient) Query(ctx context.Context, query string, ts time.Time) (model.Value, api.Warnings, error) {
	panic("implement me")
}

func (f *fakePrometheusClient) QueryRange(ctx context.Context, query string, _ v1.Range) (model.Value, api.Warnings, error) {
	f.queriesCount++
	for _, r := range f.results {
		if r.query == query {
			if r.error != nil {
				return nil, nil, r.error
			}
			return &model.String{
				Value:     r.result,
				Timestamp: model.TimeFromUnix(time.Now().Unix()),
			}, nil, nil
		}
	}
	return nil, nil, fmt.Errorf("no matching result for query: %v", query)
}

func (f fakePrometheusClient) Series(ctx context.Context, matches []string, startTime time.Time, endTime time.Time) ([]model.LabelSet, api.Warnings, error) {
	panic("implement me")
}

func (f fakePrometheusClient) Snapshot(ctx context.Context, skipHead bool) (v1.SnapshotResult, error) {
	panic("implement me")
}

func (f fakePrometheusClient) Rules(ctx context.Context) (v1.RulesResult, error) {
	panic("implement me")
}

func (f fakePrometheusClient) Targets(ctx context.Context) (v1.TargetsResult, error) {
	panic("implement me")
}

func (f fakePrometheusClient) TargetsMetadata(ctx context.Context, matchTarget string, metric string, limit string) ([]v1.MetricMetadata, error) {
	panic("implement me")
}

func TestNewPrometheusMetricObserver(t *testing.T) {
	tests := []struct {
		name                  string
		client                v1.API
		expectErr             bool
		expectQueryCount      int
		expectEventCount      int
		expectConditionStatus map[string]string
		queryHandlers         []Handler
	}{
		{
			name:             "simple query",
			expectQueryCount: 1,
			expectConditionStatus: map[string]string{
				"FooSummary_PrometheusObserverDegraded": "False",
			},
			client: &fakePrometheusClient{results: []fakeQueryResult{
				{
					query:  "sum(foo)",
					result: "10",
				},
			},
			},
			queryHandlers: []Handler{
				{
					Name: "FooSummary",
					Handler: func(ctx context.Context, recorder events.Recorder, client prometheusv1.API) error {
						result, _, _ := client.QueryRange(ctx, "sum(foo)", prometheusv1.Range{
							Start: time.Now(),
							End:   time.Now().Add(-ctx.Value("polling_interval").(time.Duration)),
						})
						if result.String() != "10" {
							t.Errorf("expected current value %q, got %q", "10", result.String())
						}
						return nil
					},
				},
			},
		},
		{
			name:             "prometheus unavailable",
			expectQueryCount: 1,
			expectConditionStatus: map[string]string{
				"PrometheusObserverDegraded":            "False",
				"FooSummary_PrometheusObserverDegraded": "Unknown",
			},
			queryHandlers: []Handler{
				{
					Name: "FooSummary",
					Handler: func(ctx context.Context, recorder events.Recorder, client prometheusv1.API) error {
						return nil
					},
				},
			},
		},
		{
			name: "simple query but failed handler",
			expectConditionStatus: map[string]string{
				"FooSummary_PrometheusObserverDegraded": "True",
			},
			client: &fakePrometheusClient{results: []fakeQueryResult{
				{
					query:  "sum(foo)",
					result: "10",
				},
			},
			},
			queryHandlers: []Handler{
				{
					Name: "FooSummary",
					Handler: func(ctx context.Context, recorder events.Recorder, client prometheusv1.API) error {
						return fmt.Errorf("handler for query failed")
					},
				},
			},
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakePromClient := func(corev1client.ServicesGetter, corev1client.SecretsGetter, corev1client.ConfigMapsGetter, routev1client.RoutesGetter) (prometheusv1.API, error) {
				return test.client, nil
			}
			fakeStaticPodOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(&operatorv1.StaticPodOperatorSpec{}, &operatorv1.StaticPodOperatorStatus{}, nil, nil)
			observer := &prometheusMetricObserver{prometheusClientFn: fakePromClient, queryHandlers: test.queryHandlers, operatorClient: fakeStaticPodOperatorClient}
			memoryRecorder := events.NewInMemoryRecorder(fmt.Sprintf("test-%d", i))
			recorder := eventstesting.NewEventRecorder(t, memoryRecorder)
			err := observer.sync(context.Background(), factory.NewSyncContext(fmt.Sprintf("test-%d", i), recorder))
			if test.expectErr && err == nil {
				t.Errorf("expected error, got none")
				return
			} else if !test.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if test.client != nil {
				if c := test.client.(*fakePrometheusClient).queriesCount; c != test.expectQueryCount {
					t.Errorf("expected %d queries, got %d", test.expectQueryCount, c)
				}
			}
			if c := len(memoryRecorder.Events()); c != test.expectEventCount {
				t.Errorf("expected %d events, got %d", test.expectEventCount, c)
			}
			_, status, _, err := fakeStaticPodOperatorClient.GetOperatorState()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			for conditionName, conditionState := range test.expectConditionStatus {
				found := false
				for _, c := range status.Conditions {
					if c.Type == conditionName && string(c.Status) == conditionState {
						t.Logf("Found %s=%q", c.Type, c.Status)
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected %s=%q, got %#v", conditionName, conditionState, status.Conditions)
				}
			}
		})
	}
}
