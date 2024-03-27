package unsupportedconfigoverridescontroller

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestKeysSetInUnsupportedConfig(t *testing.T) {
	tests := []struct {
		name string

		yaml     string
		expected sets.Set[string]
	}{
		{
			name:     "empty",
			yaml:     "",
			expected: sets.New[string](),
		},
		{
			name: "nested maps",
			yaml: `
apple:
  banana:
    carrot: hammer
`,
			expected: sets.New(
				"apple.banana.carrot",
			),
		},
		{
			name: "multiple nested maps",
			yaml: `
apple:
  banana:
    carrot: hammer
  blueberry:
    cabbage: saw
artichoke: plane
`,
			expected: sets.New(
				"apple.banana.carrot",
				"apple.blueberry.cabbage",
				"artichoke",
			),
		},
		{
			name: "multiple nested slices with nested maps",
			yaml: `
apple:
  banana:
    carrot:
    - hammer
    - chisel
    - drawknife
  blueberry:
    - saw:
      chives:
        dill: square
artichoke: plane
`,
			expected: sets.New(
				"artichoke",
				"apple.banana.carrot.0",
				"apple.banana.carrot.1",
				"apple.banana.carrot.2",
				"apple.blueberry.0.chives.dill",
				"apple.blueberry.0.saw",
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := keysSetInUnsupportedConfig([]byte(test.yaml))
			if err != nil {
				t.Fatal(err)
			}

			if !actual.Equal(test.expected) {
				t.Fatalf("missing expected %v, extra actual %v", sets.List(test.expected.Difference(actual)), sets.List(actual.Difference(test.expected)))
			}
		})
	}
}
