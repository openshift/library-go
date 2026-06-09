package health

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestWriter_Apply(t *testing.T) {
	tests := []struct {
		name       string
		nodeName   string
		conditions []PluginHealthCondition
		wantType   string
		wantMsg    string
	}{
		{
			name:     "single healthy plugin",
			nodeName: "master-0",
			conditions: []PluginHealthCondition{
				{KeyID: "1", KEKID: "key-abc", Status: "healthy", LastChecked: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
			wantType: "KMSHealthReporter_master-0",
			wantMsg:  `[{"keyID":"1","kekID":"key-abc","status":"healthy","lastChecked":"2025-01-01T00:00:00Z"}]`,
		},
		{
			name:     "mixed healthy and error",
			nodeName: "master-1",
			conditions: []PluginHealthCondition{
				{KeyID: "1", KEKID: "key-abc", Status: "healthy", LastChecked: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
				{KeyID: "2", Status: "error", Detail: "connection refused", LastChecked: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
			wantType: "KMSHealthReporter_master-1",
			wantMsg:  `[{"keyID":"1","kekID":"key-abc","status":"healthy","lastChecked":"2025-01-01T00:00:00Z"},{"keyID":"2","status":"error","lastChecked":"2025-01-01T00:00:00Z","detail":"connection refused"}]`,
		},
		{
			name:     "unhealthy plugin",
			nodeName: "master-2",
			conditions: []PluginHealthCondition{
				{KeyID: "1", Status: "unhealthy", Detail: "not ready", LastChecked: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
			wantType: "KMSHealthReporter_master-2",
			wantMsg:  `[{"keyID":"1","status":"unhealthy","lastChecked":"2025-01-01T00:00:00Z","detail":"not ready"}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := v1helpers.NewFakeOperatorClient(
				&operatorv1.OperatorSpec{},
				&operatorv1.OperatorStatus{},
				nil,
			)
			w := &Writer{operatorClient: fakeClient, nodeName: tt.nodeName}

			if err := w.Apply(context.Background(), tt.conditions); err != nil {
				t.Fatalf("Apply() error: %v", err)
			}

			_, status, _, err := fakeClient.GetOperatorState()
			if err != nil {
				t.Fatalf("GetOperatorState() error: %v", err)
			}

			if len(status.Conditions) != 1 {
				t.Fatalf("expected 1 condition, got %d", len(status.Conditions))
			}

			cond := status.Conditions[0]
			if cond.Type != tt.wantType {
				t.Errorf("condition type = %q, want %q", cond.Type, tt.wantType)
			}
			if cond.Status != operatorv1.ConditionTrue {
				t.Errorf("condition status = %q, want %q", cond.Status, operatorv1.ConditionTrue)
			}
			if cond.Reason != "AsExpected" {
				t.Errorf("condition reason = %q, want %q", cond.Reason, "AsExpected")
			}

			// Compare as parsed JSON to ignore key ordering differences.
			var gotParsed, wantParsed any
			if err := json.Unmarshal([]byte(cond.Message), &gotParsed); err != nil {
				t.Fatalf("parse condition message: %v", err)
			}
			if err := json.Unmarshal([]byte(tt.wantMsg), &wantParsed); err != nil {
				t.Fatalf("parse want message: %v", err)
			}
			gotJSON, _ := json.Marshal(gotParsed)
			wantJSON, _ := json.Marshal(wantParsed)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("condition message:\n  got:  %s\n  want: %s", gotJSON, wantJSON)
			}
		})
	}
}
