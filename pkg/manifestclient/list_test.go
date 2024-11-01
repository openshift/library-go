package manifestclient

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/diff"
)

func TestFilterByLabelSelector(t *testing.T) {
	testCases := []struct {
		name           string
		labelSelector  string
		input          *unstructured.UnstructuredList
		expectedOutput *unstructured.UnstructuredList
		expectError    bool
	}{
		{
			name:          "empty selector, match all",
			labelSelector: "",
			input: newList(
				newObj("name1", map[string]string{"app": "test1"}),
				newObj("name2", map[string]string{"team": "api"}),
			),
			expectedOutput: newList(
				newObj("name1", map[string]string{"app": "test1"}),
				newObj("name2", map[string]string{"team": "api"}),
			),
		},
		{
			name:          "single label match",
			labelSelector: "app=test1",
			input: newList(
				newObj("name1", map[string]string{"app": "test1"}),
				newObj("name2", map[string]string{"team": "api"}),
			),
			expectedOutput: newList(
				newObj("name1", map[string]string{"app": "test1"}),
			),
		},
		{
			name:          "two labels match",
			labelSelector: "app=test1,team=api",
			input: newList(
				newObj("name1", map[string]string{"app": "test1"}),
				newObj("name2", map[string]string{"team": "api"}),
				newObj("name3", map[string]string{"app": "test1", "team": "api"}),
			),
			expectedOutput: newList(
				newObj("name3", map[string]string{"app": "test1", "team": "api"}),
			),
		},
		{
			name:          "invalid label selector",
			labelSelector: "app===test1",
			input: newList(
				newObj("name1", map[string]string{"app": "test1"}),
				newObj("name2", map[string]string{"team": "api"}),
			),
			expectedOutput: nil,
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := filterByLabelSelector(tc.input, tc.labelSelector)
			if (err != nil) != tc.expectError {
				t.Errorf("Unexpected error. Got: %v, want error: %v", err, tc.expectError)
			}

			if !equality.Semantic.DeepEqual(result, tc.expectedOutput) {
				t.Errorf(diff.ObjectDiff(tc.expectedOutput, result))
			}
		})
	}

}

func newList(items ...unstructured.Unstructured) *unstructured.UnstructuredList {
	return &unstructured.UnstructuredList{Items: items}
}

func newObj(name string, labels map[string]string) unstructured.Unstructured {
	convertedLabels := make(map[string]interface{}, len(labels))
	for k, v := range labels {
		convertedLabels[k] = v
	}
	return unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":   name,
				"labels": convertedLabels,
			},
		},
	}
}
