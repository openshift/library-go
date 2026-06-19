package health

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestDynamicWriterWrite injects a fake dynamic client and asserts that write
// applies the status to the right CR coordinates: the status subresource of the
// "cluster" instance, with the reports nested under the caller-supplied path.
// This is the seam the struct unlocked: the real ApplyStatus is replaced by a
// reactor that captures the patch.
func TestDynamicWriterWrite(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "operator.openshift.io", Version: "v1", Resource: "kubeapiservers"}
	fakeClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())

	// ApplyStatus surfaces as a patch on the status subresource; capture it.
	var haveAction k8stesting.PatchAction
	fakeClient.PrependReactor("patch", "kubeapiservers", func(action k8stesting.Action) (bool, runtime.Object, error) {
		haveAction = action.(k8stesting.PatchAction)
		return true, &unstructured.Unstructured{}, nil
	})

	w := &dynamicWriter{
		client:       fakeClient,
		gvr:          gvr,
		kind:         "KubeAPIServer",
		path:         []string{"status", "encryptionStatus"},
		fieldManager: "kms-health-reporter-node-1",
	}

	checked := time.Unix(0, 0).UTC()
	status := buildEncryptionStatus("node-1", []pluginHealthReport{
		{KeyID: "1", KEKID: "kek-abc", Status: statusHealthy, LastChecked: checked},
	})

	if err := w.write(context.Background(), status); err != nil {
		t.Fatalf("write: %v", err)
	}

	if haveAction == nil {
		t.Fatal("no patch action recorded")
	}
	if have, want := haveAction.GetSubresource(), "status"; have != want {
		t.Errorf("subresource: have %q, want %q", have, want)
	}
	if have, want := haveAction.GetName(), crName; have != want {
		t.Errorf("name: have %q, want %q", have, want)
	}

	var body map[string]any
	if err := json.Unmarshal(haveAction.GetPatch(), &body); err != nil {
		t.Fatalf("unmarshal patch: %v", err)
	}
	if have, want := body["kind"], "KubeAPIServer"; have != want {
		t.Errorf("kind: have %v, want %v", have, want)
	}
	reports, found, err := unstructured.NestedSlice(body, "status", "encryptionStatus", "healthReports")
	if err != nil || !found {
		t.Fatalf("healthReports not nested under path: found=%v err=%v\nbody=%s", found, err, haveAction.GetPatch())
	}
	if have, want := len(reports), 1; have != want {
		t.Errorf("healthReports count: have %d, want %d", have, want)
	}
}
