package manifestclient_test

import (
	"testing"

	"github.com/openshift/library-go/pkg/manifestclient"
)

// TestNoPanicFromAllActionTracker
// is a simple test to ensure that the read methods
// of NewAllActionsTracker do not panic on an empty instance.
func TestNoPanicFromAllActionTracker(t *testing.T) {
	target := manifestclient.NewAllActionsTracker[manifestclient.FileOriginatedSerializedRequest]()

	if actions := target.ListActions(); len(actions) != 0 {
		t.Errorf("ListActions() returned non empty response: %v", actions)
	}

	if reqs := target.AllRequests(); len(reqs) != 0 {
		t.Errorf("AllRequests() returned non empty response: %v", reqs)
	}

	ret := target.RequestsForAction(manifestclient.ActionUpdate)
	if ret != nil {
		t.Errorf("RequestsForAction() returned non nil response: %v", ret)
	}

	ret = target.RequestsForResource(manifestclient.ActionMetadata{Action: manifestclient.ActionApply})
	if ret != nil {
		t.Errorf("RequestsForResource() returned non nil response: %v", ret)
	}

	// just make sure it doens panic
	_ = target.DeepCopy()
}
