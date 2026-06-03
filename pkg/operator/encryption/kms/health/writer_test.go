package health

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clienttesting "k8s.io/client-go/testing"

	dynamicfake "k8s.io/client-go/dynamic/fake"
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
				{KeyID: "1", KEKID: "key-abc", Status: StatusHealthy, LastChecked: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
			wantType: "KMSHealthReporter_master-0",
			wantMsg:  `[{"keyID":"1","kekID":"key-abc","status":"healthy","lastChecked":"2025-01-01T00:00:00Z"}]`,
		},
		{
			name:     "mixed healthy and error",
			nodeName: "master-1",
			conditions: []PluginHealthCondition{
				{KeyID: "1", KEKID: "key-abc", Status: StatusHealthy, LastChecked: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
				{KeyID: "2", Status: StatusError, Detail: "connection refused", LastChecked: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
			wantType: "KMSHealthReporter_master-1",
			wantMsg:  `[{"keyID":"1","kekID":"key-abc","status":"healthy","lastChecked":"2025-01-01T00:00:00Z"},{"keyID":"2","status":"error","lastChecked":"2025-01-01T00:00:00Z","detail":"connection refused"}]`,
		},
		{
			name:     "unhealthy plugin",
			nodeName: "master-2",
			conditions: []PluginHealthCondition{
				{KeyID: "1", Status: StatusUnhealthy, Detail: "not ready", LastChecked: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
			wantType: "KMSHealthReporter_master-2",
			wantMsg:  `[{"keyID":"1","status":"unhealthy","lastChecked":"2025-01-01T00:00:00Z","detail":"not ready"}]`,
		},
	}

	gvr := schema.GroupVersionResource{Group: "operator.openshift.io", Version: "v1", Resource: "kubeapiservers"}
	gvk := schema.GroupVersionKind{Group: "operator.openshift.io", Version: "v1", Kind: "KubeAPIServer"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			fakeClient := dynamicfake.NewSimpleDynamicClient(scheme)

			var captured *unstructured.Unstructured
			fakeClient.PrependReactor("patch", "kubeapiservers", func(action clienttesting.Action) (bool, runtime.Object, error) {
				patchAction := action.(clienttesting.PatchAction)
				obj := &unstructured.Unstructured{}
				if err := json.Unmarshal(patchAction.GetPatch(), &obj.Object); err != nil {
					t.Fatalf("unmarshal patch: %v", err)
				}
				captured = obj
				return true, obj, nil
			})

			w := &Writer{
				client:   fakeClient.Resource(gvr),
				gvk:      gvk,
				nodeName: tt.nodeName,
			}

			if err := w.Apply(context.Background(), tt.conditions); err != nil {
				t.Fatalf("Apply() error: %v", err)
			}

			if captured == nil {
				t.Fatal("no patch was issued")
			}

			statusObj, ok := captured.Object["status"]
			if !ok {
				t.Fatal("no status in patch")
			}
			statusMap, ok := statusObj.(map[string]interface{})
			if !ok {
				t.Fatal("status is not a map")
			}
			conditionsRaw, ok := statusMap["conditions"]
			if !ok {
				t.Fatal("no conditions in status")
			}
			condList, ok := conditionsRaw.([]interface{})
			if !ok {
				t.Fatalf("conditions is not a list, got %T", conditionsRaw)
			}
			if len(condList) != 1 {
				t.Fatalf("expected 1 condition, got %d", len(condList))
			}

			condMap := condList[0].(map[string]interface{})
			if got := condMap["type"]; got != tt.wantType {
				t.Errorf("condition type = %q, want %q", got, tt.wantType)
			}
			if got := condMap["status"]; got != "True" {
				t.Errorf("condition status = %q, want %q", got, "True")
			}
			if got := condMap["reason"]; got != "AsExpected" {
				t.Errorf("condition reason = %q, want %q", got, "AsExpected")
			}

			var gotParsed, wantParsed interface{}
			if err := json.Unmarshal([]byte(condMap["message"].(string)), &gotParsed); err != nil {
				t.Fatalf("parse condition message: %v", err)
			}
			if err := json.Unmarshal([]byte(tt.wantMsg), &wantParsed); err != nil {
				t.Fatalf("parse want message: %v", err)
			}
			if !reflect.DeepEqual(gotParsed, wantParsed) {
				t.Errorf("condition message:\n  got:  %s\n  want: %s", condMap["message"], tt.wantMsg)
			}

			// Verify SSA patch type
			for _, a := range fakeClient.Actions() {
				if pa, ok := a.(clienttesting.PatchAction); ok {
					if pa.GetPatchType() != "application/apply-patch+yaml" {
						t.Errorf("patch type = %q, want application/apply-patch+yaml", pa.GetPatchType())
					}
				}
			}
		})
	}
}
