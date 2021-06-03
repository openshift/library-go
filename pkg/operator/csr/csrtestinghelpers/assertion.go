package csrtestinghelpers

import (
	"testing"

	clienttesting "k8s.io/client-go/testing"
)

// AssertError asserts the actual error representation is the same with the expected,
// if the expected error representation is empty, the actual should be nil
func AssertError(t *testing.T, actual error, expectedErr string) {
	if len(expectedErr) > 0 && actual == nil {
		t.Errorf("expected %q error", expectedErr)
		return
	}
	if len(expectedErr) > 0 && actual != nil && actual.Error() != expectedErr {
		t.Errorf("expected %q error, but got %q", expectedErr, actual.Error())
		return
	}
	if len(expectedErr) == 0 && actual != nil {
		t.Errorf("unexpected err: %v", actual)
		return
	}
}

// AssertActions asserts the actual actions have the expected action verb
func AssertActions(t *testing.T, actualActions []clienttesting.Action, expectedVerbs ...string) {
	if len(actualActions) != len(expectedVerbs) {
		t.Fatalf("expected %d call but got: %#v", len(expectedVerbs), actualActions)
	}
	for i, expected := range expectedVerbs {
		if actualActions[i].GetVerb() != expected {
			t.Errorf("expected %s action but got: %#v", expected, actualActions[i])
		}
	}
}

// AssertNoActions asserts no actions are happened
func AssertNoActions(t *testing.T, actualActions []clienttesting.Action) {
	AssertActions(t, actualActions)
}
