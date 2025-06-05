package v1helpers

import (
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"

	operatorsv1 "github.com/openshift/api/operator/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
)

func newOperatorCondition(name, status, reason, message string, lastTransition *metav1.Time) operatorsv1.OperatorCondition {
	ret := operatorsv1.OperatorCondition{
		Type:    name,
		Status:  operatorsv1.ConditionStatus(status),
		Reason:  reason,
		Message: message,
	}
	if lastTransition != nil {
		ret.LastTransitionTime = *lastTransition
	}

	return ret
}

func TestSetOperatorCondition(t *testing.T) {
	nowish := metav1.Now()
	beforeish := metav1.Time{Time: nowish.Add(-10 * time.Second)}
	afterish := metav1.Time{Time: nowish.Add(10 * time.Second)}

	tests := []struct {
		name         string
		starting     []operatorsv1.OperatorCondition
		newCondition operatorsv1.OperatorCondition
		expected     []operatorsv1.OperatorCondition
	}{
		{
			name:         "add to empty",
			starting:     []operatorsv1.OperatorCondition{},
			newCondition: newOperatorCondition("one", "True", "my-reason", "my-message", nil),
			expected: []operatorsv1.OperatorCondition{
				newOperatorCondition("one", "True", "my-reason", "my-message", nil),
			},
		},
		{
			name: "add to non-conflicting",
			starting: []operatorsv1.OperatorCondition{
				newOperatorCondition("two", "True", "my-reason", "my-message", nil),
			},
			newCondition: newOperatorCondition("one", "True", "my-reason", "my-message", nil),
			expected: []operatorsv1.OperatorCondition{
				newOperatorCondition("two", "True", "my-reason", "my-message", nil),
				newOperatorCondition("one", "True", "my-reason", "my-message", nil),
			},
		},
		{
			name: "change existing status",
			starting: []operatorsv1.OperatorCondition{
				newOperatorCondition("two", "True", "my-reason", "my-message", nil),
				newOperatorCondition("one", "True", "my-reason", "my-message", nil),
			},
			newCondition: newOperatorCondition("one", "False", "my-different-reason", "my-othermessage", nil),
			expected: []operatorsv1.OperatorCondition{
				newOperatorCondition("two", "True", "my-reason", "my-message", nil),
				newOperatorCondition("one", "False", "my-different-reason", "my-othermessage", nil),
			},
		},
		{
			name: "leave existing transition time",
			starting: []operatorsv1.OperatorCondition{
				newOperatorCondition("two", "True", "my-reason", "my-message", nil),
				newOperatorCondition("one", "True", "my-reason", "my-message", &beforeish),
			},
			newCondition: newOperatorCondition("one", "True", "my-reason", "my-message", &afterish),
			expected: []operatorsv1.OperatorCondition{
				newOperatorCondition("two", "True", "my-reason", "my-message", nil),
				newOperatorCondition("one", "True", "my-reason", "my-message", &beforeish),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetOperatorCondition(&test.starting, test.newCondition)
			if len(test.starting) != len(test.expected) {
				t.Fatal(spew.Sdump(test.starting))
			}

			for i := range test.expected {
				expected := test.expected[i]
				actual := test.starting[i]
				if expected.LastTransitionTime == (metav1.Time{}) {
					actual.LastTransitionTime = metav1.Time{}
				}
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(diff.ObjectDiff(expected, actual))
				}
			}
		})
	}
}

func TestRemoveOperatorCondition(t *testing.T) {
	tests := []struct {
		name            string
		starting        []operatorsv1.OperatorCondition
		removeCondition string
		expected        []operatorsv1.OperatorCondition
	}{
		{
			name:            "remove missing",
			starting:        []operatorsv1.OperatorCondition{},
			removeCondition: "one",
			expected:        []operatorsv1.OperatorCondition{},
		},
		{
			name: "remove existing",
			starting: []operatorsv1.OperatorCondition{
				newOperatorCondition("two", "True", "my-reason", "my-message", nil),
				newOperatorCondition("one", "True", "my-reason", "my-message", nil),
			},
			removeCondition: "two",
			expected: []operatorsv1.OperatorCondition{
				newOperatorCondition("one", "True", "my-reason", "my-message", nil),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			RemoveOperatorCondition(&test.starting, test.removeCondition)
			if len(test.starting) != len(test.expected) {
				t.Fatal(spew.Sdump(test.starting))
			}

			for i := range test.expected {
				expected := test.expected[i]
				actual := test.starting[i]
				if expected.LastTransitionTime == (metav1.Time{}) {
					actual.LastTransitionTime = metav1.Time{}
				}
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(diff.ObjectDiff(expected, actual))
				}
			}
		})
	}
}

func newCondition(name, status, reason, message string, lastTransition *metav1.Time) metav1.Condition {
	ret := metav1.Condition{
		Type:    name,
		Status:  metav1.ConditionStatus(status),
		Reason:  reason,
		Message: message,
	}
	if lastTransition != nil {
		ret.LastTransitionTime = *lastTransition
	}

	return ret
}

func TestSetCondition(t *testing.T) {
	nowish := metav1.Now()
	beforeish := metav1.Time{Time: nowish.Add(-10 * time.Second)}
	afterish := metav1.Time{Time: nowish.Add(10 * time.Second)}

	tests := []struct {
		name         string
		starting     []metav1.Condition
		newCondition metav1.Condition
		expected     []metav1.Condition
	}{
		{
			name:         "add to empty",
			starting:     []metav1.Condition{},
			newCondition: newCondition("one", "True", "my-reason", "my-message", nil),
			expected: []metav1.Condition{
				newCondition("one", "True", "my-reason", "my-message", nil),
			},
		},
		{
			name: "add to non-conflicting",
			starting: []metav1.Condition{
				newCondition("two", "True", "my-reason", "my-message", nil),
			},
			newCondition: newCondition("one", "True", "my-reason", "my-message", nil),
			expected: []metav1.Condition{
				newCondition("two", "True", "my-reason", "my-message", nil),
				newCondition("one", "True", "my-reason", "my-message", nil),
			},
		},
		{
			name: "change existing status",
			starting: []metav1.Condition{
				newCondition("two", "True", "my-reason", "my-message", nil),
				newCondition("one", "True", "my-reason", "my-message", nil),
			},
			newCondition: newCondition("one", "False", "my-different-reason", "my-othermessage", nil),
			expected: []metav1.Condition{
				newCondition("two", "True", "my-reason", "my-message", nil),
				newCondition("one", "False", "my-different-reason", "my-othermessage", nil),
			},
		},
		{
			name: "leave existing transition time",
			starting: []metav1.Condition{
				newCondition("two", "True", "my-reason", "my-message", nil),
				newCondition("one", "True", "my-reason", "my-message", &beforeish),
			},
			newCondition: newCondition("one", "True", "my-reason", "my-message", &afterish),
			expected: []metav1.Condition{
				newCondition("two", "True", "my-reason", "my-message", nil),
				newCondition("one", "True", "my-reason", "my-message", &beforeish),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetCondition(&test.starting, test.newCondition)
			if len(test.starting) != len(test.expected) {
				t.Fatal(spew.Sdump(test.starting))
			}

			for i := range test.expected {
				expected := test.expected[i]
				actual := test.starting[i]
				if expected.LastTransitionTime == (metav1.Time{}) {
					actual.LastTransitionTime = metav1.Time{}
				}
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(diff.ObjectDiff(expected, actual))
				}
			}
		})
	}
}

func TestRemoveCondition(t *testing.T) {
	tests := []struct {
		name            string
		starting        []metav1.Condition
		removeCondition string
		expected        []metav1.Condition
	}{
		{
			name:            "remove missing",
			starting:        []metav1.Condition{},
			removeCondition: "one",
			expected:        []metav1.Condition{},
		},
		{
			name: "remove existing",
			starting: []metav1.Condition{
				newCondition("two", "True", "my-reason", "my-message", nil),
				newCondition("one", "True", "my-reason", "my-message", nil),
			},
			removeCondition: "two",
			expected: []metav1.Condition{
				newCondition("one", "True", "my-reason", "my-message", nil),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			RemoveCondition(&test.starting, test.removeCondition)
			if len(test.starting) != len(test.expected) {
				t.Fatal(spew.Sdump(test.starting))
			}

			for i := range test.expected {
				expected := test.expected[i]
				actual := test.starting[i]
				if expected.LastTransitionTime == (metav1.Time{}) {
					actual.LastTransitionTime = metav1.Time{}
				}
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(diff.ObjectDiff(expected, actual))
				}
			}
		})
	}
}

func TestRemoveConditionsJSONPatch(t *testing.T) {
	operatorStatus := &operatorsv1.OperatorStatus{
		Conditions: []operatorsv1.OperatorCondition{
			newOperatorCondition("one", "True", "my-reason", "my-message", nil),
			newOperatorCondition("two", "True", "my-reason", "my-message", nil),
			newOperatorCondition("three", "True", "my-reason", "my-message", nil),
		},
	}

	t.Run("nil status", func(tt *testing.T) {
		jsonPatch := RemoveConditionsJSONPatch(nil, []string{"four", "five"})
		if jsonPatch != nil {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected nil patch, got: %s", string(raw))
		}
	})

	t.Run("no conditions", func(tt *testing.T) {
		jsonPatch := RemoveConditionsJSONPatch(&operatorsv1.OperatorStatus{}, []string{"four", "five"})
		if !jsonPatch.IsEmpty() {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected empty patch; got: %s", string(raw))
		}
	})

	t.Run("no conditions but patch not empty", func(tt *testing.T) {
		jsonPatch := RemoveConditionsJSONPatch(&operatorsv1.OperatorStatus{}, []string{"four", "five"})
		if !jsonPatch.IsEmpty() {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected empty patch; got: %s", string(raw))
		}
	})

	t.Run("nothing to remove", func(tt *testing.T) {
		jsonPatch := RemoveConditionsJSONPatch(operatorStatus, []string{})
		if jsonPatch != nil {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected nil patch, got: %s", string(raw))
		}
	})

	t.Run("no conditions found to remove", func(tt *testing.T) {
		jsonPatch := RemoveConditionsJSONPatch(operatorStatus, []string{"four", "five"})
		if !jsonPatch.IsEmpty() {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected empty patch; got: %s", string(raw))
		}
	})

	t.Run("remove one", func(tt *testing.T) {
		jsonPatch := RemoveConditionsJSONPatch(operatorStatus, []string{"two", "four"})
		raw, err := jsonPatch.Marshal()
		if err != nil {
			tt.Fatalf("could not marshal json patch: %v", err)
		}

		expectedJSONPatch := `[{"op":"test","path":"/status/conditions/1/type","value":"two"},{"op":"remove","path":"/status/conditions/1"}]`
		if expectedJSONPatch != string(raw) {
			tt.Errorf("unexpected json patch: %s", diff.ObjectDiff(expectedJSONPatch, string(raw)))
		}
	})

	t.Run("remove all", func(tt *testing.T) {
		jsonPatch := RemoveConditionsJSONPatch(operatorStatus, []string{"one", "two", "three", "four"})
		raw, err := jsonPatch.Marshal()
		if err != nil {
			tt.Fatalf("could not marshal json patch: %v", err)
		}

		expectedJSONPatch := `[{"op":"test","path":"/status/conditions/0/type","value":"one"},{"op":"remove","path":"/status/conditions/0"},{"op":"test","path":"/status/conditions/0/type","value":"two"},{"op":"remove","path":"/status/conditions/0"},{"op":"test","path":"/status/conditions/0/type","value":"three"},{"op":"remove","path":"/status/conditions/0"}]`
		if expectedJSONPatch != string(raw) {
			tt.Errorf("unexpected json patch: %s", diff.ObjectDiff(expectedJSONPatch, string(raw)))
		}
	})
}

func TestRemoveWorkloadGenerationsJSONPatch(t *testing.T) {
	operatorStatus := &operatorsv1.OperatorStatus{
		Generations: []operatorsv1.GenerationStatus{
			{
				Group:     "apps",
				Resource:  "deployments",
				Name:      "test",
				Namespace: "test-ns",
			},
			{
				Group:     "apps2",
				Resource:  "deployments2",
				Name:      "test2",
				Namespace: "test-ns2",
			},
		},
	}

	t.Run("nil status", func(tt *testing.T) {
		jsonPatch := RemoveWorkloadGenerationsJSONPatch(nil, "test", "test")
		if jsonPatch != nil {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected nil patch, got: %s", string(raw))
		}
	})

	t.Run("empty name arg", func(tt *testing.T) {
		jsonPatch := RemoveWorkloadGenerationsJSONPatch(operatorStatus, "", "test")
		if jsonPatch != nil {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected nil patch, got: %s", string(raw))
		}
	})

	t.Run("empty namespace arg", func(tt *testing.T) {
		jsonPatch := RemoveWorkloadGenerationsJSONPatch(operatorStatus, "test", "")
		if jsonPatch != nil {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected nil patch, got: %s", string(raw))
		}
	})

	t.Run("no generations to remove group and resource matching", func(tt *testing.T) {
		jsonPatch := RemoveWorkloadGenerationsJSONPatch(operatorStatus, "test1", "test1-ns")
		if !jsonPatch.IsEmpty() {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected nil patch, got: %s", string(raw))
		}
	})

	t.Run("no generations to remove group and resource different", func(tt *testing.T) {
		jsonPatch := RemoveWorkloadGenerationsJSONPatch(operatorStatus, "test2", "test2-ns")
		if !jsonPatch.IsEmpty() {
			raw, err := jsonPatch.Marshal()
			if err != nil {
				tt.Fatalf("could not marshal json patch: %v", err)
			}
			tt.Errorf("expected nil patch, got: %s", string(raw))
		}
	})

	t.Run("remove one", func(tt *testing.T) {
		jsonPatch := RemoveWorkloadGenerationsJSONPatch(operatorStatus, "test", "test-ns")
		if jsonPatch.IsEmpty() {
			t.Errorf("expected non-empty patch, got empty")
		}

		raw, err := jsonPatch.Marshal()
		if err != nil {
			tt.Fatalf("could not marshal json patch: %v", err)
		}

		expectedJSONPatch := `[{"op":"test","path":"/status/generations/0/namespace","value":"test-ns"},{"op":"test","path":"/status/generations/0/group","value":"apps"},{"op":"test","path":"/status/generations/0/resource","value":"deployments"},{"op":"test","path":"/status/generations/0/name","value":"test"},{"op":"remove","path":"/status/generations/0"}]`
		if expectedJSONPatch != string(raw) {
			tt.Errorf("unexpected json patch: %s", diff.ObjectDiff(expectedJSONPatch, string(raw)))
		}
	})
}
