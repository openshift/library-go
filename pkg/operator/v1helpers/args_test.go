package v1helpers

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/diff"
)

func TestFlagsFromUnstructured(t *testing.T) {
	scenarios := []struct {
		name           string
		input          map[string]interface{}
		expectedOutput map[string][]string
		expectedError  bool
	}{
		{
			name: "no-op",
		},

		{
			name: "simple input",
			input: map[string]interface{}{
				"a": "aval", "b": []interface{}{"bval"},
			},
			expectedOutput: map[string][]string{
				"a": {"aval"}, "b": {"bval"},
			},
		},

		{
			name: "simple input 2",
			input: map[string]interface{}{
				"a": "/localhost(:|$)", "b": []interface{}{"/127\\.0\\.0\\.1(:|$)"},
			},
			expectedOutput: map[string][]string{
				"a": {"/localhost(:|$)"}, "b": {"/127\\.0\\.0\\.1(:|$)"},
			},
		},

		{
			name: "incorrect input",
			input: map[string]interface{}{
				"a": []string{"aval"},
			},
			expectedError: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			actualOutput, err := FlagsFromUnstructured(scenario.input)

			// validate
			if err == nil && scenario.expectedError {
				t.Fatal("expected to get an error from FlagsFromUnstructured() function")
			}
			if err != nil && !scenario.expectedError {
				t.Fatal(err)
			}

			if !equality.Semantic.DeepEqual(actualOutput, scenario.expectedOutput) {
				t.Errorf("%s", diff.Diff(actualOutput, scenario.expectedOutput))
			}
		})
	}
}

func TestToFlagSlice(t *testing.T) {
	scenarios := []struct {
		name           string
		input          map[string][]string
		expectedOutput []string
	}{
		{
			name: "no-op",
		},

		{
			name:           "single value",
			input:          map[string][]string{"master": {"localhost"}},
			expectedOutput: []string{"--master=localhost"},
		},

		{
			name:           "multiple values",
			input:          map[string][]string{"master": {"localhost", "10.0.0.1"}},
			expectedOutput: []string{"--master=localhost", "--master=10.0.0.1"},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			actualOutput := ToFlagSlice(scenario.input)

			// validate
			if !equality.Semantic.DeepEqual(actualOutput, scenario.expectedOutput) {
				t.Errorf("%s", diff.Diff(actualOutput, scenario.expectedOutput))
			}
		})
	}
}
