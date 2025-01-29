package jsonpatch

import (
	"fmt"
	"testing"
)

func TestIsEmpty(t *testing.T) {
	target := New()
	if !target.IsEmpty() {
		t.Fatal("expected the patch to be empty")
	}

	target.WithTest("foo", "bar")
	if target.IsEmpty() {
		t.Fatal("expected the patch to be NOT empty")
	}
}

func TestJSONPatchNegative(t *testing.T) {
	scenarios := []struct {
		name          string
		target        *PatchSet
		expectedError error
	}{
		{
			name:          "test for resourceVersion is forbidden",
			target:        New().WithTest("/metadata/resourceVersion", "1"),
			expectedError: fmt.Errorf(`test operation at index: 0 contains forbidden path: "/metadata/resourceVersion"`),
		},
		{
			name: "multiple test for resourceVersion is forbidden",
			target: New().
				WithTest("/metadata/resourceVersion", "1").
				WithTest("/status/condition", "foo").
				WithTest("/metadata/resourceVersion", "2"),
			expectedError: fmt.Errorf(`[test operation at index: 0 contains forbidden path: "/metadata/resourceVersion", test operation at index: 2 contains forbidden path: "/metadata/resourceVersion"]`),
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			patchBytes, err := scenario.target.Marshal()
			if err.Error() != scenario.expectedError.Error() {
				t.Fatalf("unexpected err: %v, expected: %v", err.Error(), scenario.expectedError.Error())
			}
			if len(patchBytes) > 0 {
				t.Fatal("didn't expect any output")
			}
		})
	}
}

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
			target:         New().WithTest("/status/condition", "foo"),
			expectedOutput: `[{"op":"test","path":"/status/condition","value":"foo"}]`,
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
