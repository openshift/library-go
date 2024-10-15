package jsonpatch

import (
	"testing"
)

func TestJSONPatch(t *testing.T) {
	scenarios := []struct {
		name           string
		target         *PatchSet
		expectedOutput string
	}{
		{
			name:           "empty patch works and encodes as the null JSON value",
			target:         New(),
			expectedOutput: "null",
		},
		{
			name:           "patch WithTest",
			target:         New().WithTest("/metadata/resourceVersion", "1234"),
			expectedOutput: `[{"op":"test","path":"/metadata/resourceVersion","value":"1234"}]`,
		},
		{
			name:           "patch WithTest and WithRemove",
			target:         New().WithRemove("/status/foo", NewTestCondition("/status/condition", "bar")),
			expectedOutput: `[{"op":"test","path":"/status/condition","value":"bar"},{"op":"remove","path":"/status/foo"}]`,
		},
		{
			name:           "patch WithTest and WithRemove multiple times same test",
			target:         New().WithRemove("/status/foo", NewTestCondition("/status/condition", "bar")).WithRemove("/status/bar", NewTestCondition("/status/condition", "bar")),
			expectedOutput: `[{"op":"test","path":"/status/condition","value":"bar"},{"op":"remove","path":"/status/foo"},{"op":"test","path":"/status/condition","value":"bar"},{"op":"remove","path":"/status/bar"}]`,
		},
		{
			name:           "patch WithTest and WithRemove multiple times different test",
			target:         New().WithRemove("/status/foo", NewTestCondition("/status/condition", "bar")).WithRemove("/status/bar", NewTestCondition("/status/condition", "foo")),
			expectedOutput: `[{"op":"test","path":"/status/condition","value":"bar"},{"op":"remove","path":"/status/foo"},{"op":"test","path":"/status/condition","value":"foo"},{"op":"remove","path":"/status/bar"}]`,
		},
		{
			name:           "patch WithTest multiple times",
			target:         New().WithTest("/status/secondCondition", "foo").WithRemove("/status/foo", NewTestCondition("/status/condition", "bar")),
			expectedOutput: `[{"op":"test","path":"/status/secondCondition","value":"foo"},{"op":"test","path":"/status/condition","value":"bar"},{"op":"remove","path":"/status/foo"}]`,
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			patchBytes, err := scenario.target.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if string(patchBytes) != scenario.expectedOutput {
				t.Fatalf("expected = %s, got = %s", scenario.expectedOutput, patchBytes)
			}
		})
	}
}
