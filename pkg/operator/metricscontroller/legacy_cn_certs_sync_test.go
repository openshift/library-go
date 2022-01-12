package metricscontroller

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	prometheusv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	prometheusmodel "github.com/prometheus/common/model"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type nopCloser struct{}

func (n *nopCloser) CloseIdleConnections() {}

type mockPrometheusClient struct {
	prometheusv1.API

	queryResult prometheusmodel.Value
	queryError  error
}

func (m *mockPrometheusClient) Query(ctx context.Context, query string, ts time.Time) (prometheusmodel.Value, prometheusv1.Warnings, error) {
	return m.queryResult, nil, m.queryError
}

func TestLegacyCNCertsController(t *testing.T) {
	for _, tc := range []struct {
		name           string
		queryResult    prometheusmodel.Value
		queryError     error
		wantSyncError  string
		wantConditions []operatorv1.OperatorCondition
	}{
		{
			name: "vector - valid certs",
			queryResult: prometheusmodel.Vector([]*prometheusmodel.Sample{
				{
					Value: 0.0,
				},
				{
					// second vector value exposes invalid certs,
					// however the first one is picked.
					Value: 1.0,
				},
			}),
			wantConditions: []operatorv1.OperatorCondition{
				{
					Type:   "InvalidCertsUpgradeable",
					Status: "True",
				},
			},
		},
		{
			name: "vector - invalid certs",
			queryResult: prometheusmodel.Vector([]*prometheusmodel.Sample{
				{
					Value: 1.0,
				},
				{
					// second vector value exposes no invalid certs,
					// however the first one is picked.
					Value: 0.0,
				},
			}),
			wantConditions: []operatorv1.OperatorCondition{
				{
					Type:    "InvalidCertsUpgradeable",
					Status:  "False",
					Message: "1 server certificates without SAN detected",
					Reason:  "InvalidCertsDetected",
				},
			},
		},
		{
			name: "scalar - valid certs",
			queryResult: &prometheusmodel.Scalar{
				Value: 0.0,
			},
			wantConditions: []operatorv1.OperatorCondition{
				{
					Type:   "InvalidCertsUpgradeable",
					Status: "True",
				},
			},
		},
		{
			name: "scalar - invalid certs",
			queryResult: &prometheusmodel.Scalar{
				Value: 10.0,
			},
			wantConditions: []operatorv1.OperatorCondition{
				{
					Type:    "InvalidCertsUpgradeable",
					Status:  "False",
					Message: "10 server certificates without SAN detected",
					Reason:  "InvalidCertsDetected",
				},
			},
		},
		{
			name:          "scalar - invalid type",
			queryResult:   &prometheusmodel.String{Value: "foo"},
			wantSyncError: "unexpected prometheus query return type: *model.String",
		},
		{
			name:          "prometheus failure",
			queryError:    errors.New("prometheus exploded"),
			wantSyncError: "error executing prometheus query: prometheus exploded",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &mockPrometheusClient{
				queryResult: tc.queryResult,
				queryError:  tc.queryError,
			}

			client := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil)

			c := &metricsController{
				operatorClient: client,
				newPrometheusClientFunc: func() (prometheusv1.API, idleConnectionCloser, error) {
					return m, &nopCloser{}, nil
				},
				metricsSyncFunc: NewLegacyCNCertsMetricsSyncFunc("", client),
			}

			gotSyncErr := ""
			if err := c.sync(context.Background(), factory.NewSyncContext(tc.name, events.NewInMemoryRecorder(tc.name))); err != nil {
				gotSyncErr = err.Error()
			}

			if gotSyncErr != tc.wantSyncError {
				t.Fatalf("got sync error %q, want %q", gotSyncErr, tc.wantSyncError)
			}

			_, status, _, err := client.GetOperatorState()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for i := range status.Conditions {
				status.Conditions[i].LastTransitionTime = metav1.Time{}
			}

			if got := status.Conditions; !reflect.DeepEqual(got, tc.wantConditions) {
				t.Errorf("got conditions %+v, want %+v", got, tc.wantConditions)
			}
		})
	}
}
