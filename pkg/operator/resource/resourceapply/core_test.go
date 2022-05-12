package resourceapply

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/openshift/library-go/pkg/operator/events"
)

func TestApplyConfigMap(t *testing.T) {
	tests := []struct {
		name     string
		existing []runtime.Object
		input    *corev1.ConfigMap

		expectedModified bool
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name: "create",
			input: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo"},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "configmaps") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "configmaps") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo"},
				}
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.ConfigMap)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "skip on extra label",
			existing: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"extra": "leave-alone"}},
				},
			},
			input: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo"},
			},

			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "configmaps") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "don't mutate CA bundle if injected",
			existing: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"config.openshift.io/inject-trusted-cabundle": "true"}},
					Data: map[string]string{
						"ca-bundle.crt": "value",
					},
				},
			},
			input: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"config.openshift.io/inject-trusted-cabundle": "true"}},
			},

			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "configmaps") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "keep CA bundle if injected, but prune other entries",
			existing: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"config.openshift.io/inject-trusted-cabundle": "true"}},
					Data: map[string]string{
						"ca-bundle.crt": "value",
						"other":         "something",
					},
				},
			},
			input: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"config.openshift.io/inject-trusted-cabundle": "true"}},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "configmaps") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "configmaps") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"config.openshift.io/inject-trusted-cabundle": "true"}},
					Data: map[string]string{
						"ca-bundle.crt": "value",
					},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "mutate CA bundle if injected, but ca-bundle.crt specified",
			existing: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"config.openshift.io/inject-trusted-cabundle": "true"}},
					Data: map[string]string{
						"ca-bundle.crt": "value",
					},
				},
			},
			input: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"config.openshift.io/inject-trusted-cabundle": "true"}},
				Data: map[string]string{
					"ca-bundle.crt": "different",
				},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "configmaps") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "configmaps") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"config.openshift.io/inject-trusted-cabundle": "true"}},
					Data: map[string]string{
						"ca-bundle.crt": "different",
					},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update on missing label",
			existing: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"extra": "leave-alone"}},
				},
			},
			input: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"new": "merge"}},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "configmaps") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "configmaps") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"extra": "leave-alone", "new": "merge"}},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update on mismatch data",
			existing: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"extra": "leave-alone"}},
				},
			},
			input: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo"},
				Data: map[string]string{
					"configmap": "value",
				},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "configmaps") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "configmaps") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"extra": "leave-alone"}},
					Data: map[string]string{
						"configmap": "value",
					},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update on mismatch binary data",
			existing: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"extra": "leave-alone"}},
					Data: map[string]string{
						"configmap": "value",
					},
				},
			},
			input: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo"},
				Data: map[string]string{
					"configmap": "value",
				},
				BinaryData: map[string][]byte{
					"binconfigmap": []byte("value"),
				},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "configmaps") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "configmaps") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "one-ns", Name: "foo", Labels: map[string]string{"extra": "leave-alone"}},
					Data: map[string]string{
						"configmap": "value",
					},
					BinaryData: map[string][]byte{
						"binconfigmap": []byte("value"),
					},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.ConfigMap)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			_, actualModified, err := ApplyConfigMap(context.TODO(), client.CoreV1(), events.NewInMemoryRecorder("test"), test.input)
			if err != nil {
				t.Fatal(err)
			}
			if test.expectedModified != actualModified {
				t.Errorf("expected %v, got %v", test.expectedModified, actualModified)
			}
			test.verifyActions(client.Actions(), t)
		})
	}
}

func TestApplySecret(t *testing.T) {
	m := metav1.ObjectMeta{
		Name:        "test",
		Namespace:   "default",
		Annotations: map[string]string{},
	}

	r := schema.GroupVersionResource{Group: "", Resource: "secrets", Version: "v1"}

	tt := []struct {
		name     string
		existing []runtime.Object
		required *corev1.Secret
		expected *corev1.Secret
		actions  []clienttesting.Action
		changed  bool
		err      error
	}{
		{
			name:     "secret gets created if it doesn't exist",
			existing: nil,
			required: &corev1.Secret{
				ObjectMeta: m,
				Type:       corev1.SecretTypeTLS,
			},
			changed: true,
			expected: &corev1.Secret{
				ObjectMeta: m,
				Type:       corev1.SecretTypeTLS,
			},
			actions: []clienttesting.Action{
				clienttesting.GetActionImpl{
					Name: m.Name,
					ActionImpl: clienttesting.ActionImpl{
						Namespace: m.Namespace,
						Verb:      "get",
						Resource:  r,
					},
				},
				clienttesting.CreateActionImpl{
					ActionImpl: clienttesting.ActionImpl{
						Namespace: m.Namespace,
						Verb:      "create",
						Resource:  r,
					},
					Object: &corev1.Secret{
						ObjectMeta: m,
						Type:       corev1.SecretTypeTLS,
					},
				},
			},
		},
		{
			name: "replaces data",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: m,
					Type:       corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"foo": []byte("aaa"),
					},
				},
			},
			required: &corev1.Secret{
				ObjectMeta: m,
				Type:       corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"bar": []byte("bbb"),
				},
			},
			changed: true,
			expected: &corev1.Secret{
				ObjectMeta: m,
				Type:       corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"bar": []byte("bbb"),
				},
			},
			actions: []clienttesting.Action{
				clienttesting.GetActionImpl{
					Name: m.Name,
					ActionImpl: clienttesting.ActionImpl{
						Namespace: m.Namespace,
						Verb:      "get",
						Resource:  r,
					},
				},
				clienttesting.UpdateActionImpl{
					ActionImpl: clienttesting.ActionImpl{
						Namespace: m.Namespace,
						Verb:      "update",
						Resource:  r,
					},
					Object: &corev1.Secret{
						ObjectMeta: m,
						Type:       corev1.SecretTypeTLS,
						Data: map[string][]byte{
							"bar": []byte("bbb"),
						},
					},
				},
			},
		},
		{
			name: "doesn't replace existing data for service account tokens",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: m,
					Type:       corev1.SecretTypeServiceAccountToken,
					Data: map[string][]byte{
						"tls.key": []byte("aaa"),
					},
				},
			},
			required: &corev1.Secret{
				ObjectMeta: m,
				Type:       corev1.SecretTypeServiceAccountToken,
				Data:       nil,
			},
			changed: false,
			expected: &corev1.Secret{
				ObjectMeta: m,
				Type:       corev1.SecretTypeServiceAccountToken,
				Data: map[string][]byte{
					"tls.key": []byte("aaa"),
				},
			},
			actions: []clienttesting.Action{
				clienttesting.GetActionImpl{
					Name: m.Name,
					ActionImpl: clienttesting.ActionImpl{
						Namespace: m.Namespace,
						Verb:      "get",
						Resource:  r,
					},
				},
			},
		},
		{
			name: "recreates the secret if its type changes",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: m,
					Type:       "",
					Data: map[string][]byte{
						"foo": []byte("bar"),
					},
				},
			},
			required: &corev1.Secret{
				ObjectMeta: m,
				Type:       corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"foo": []byte("bar"),
				},
			},
			changed: true,
			expected: &corev1.Secret{
				ObjectMeta: m,
				Type:       corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"foo": []byte("bar"),
				},
			},
			actions: []clienttesting.Action{
				clienttesting.GetActionImpl{
					Name: m.Name,
					ActionImpl: clienttesting.ActionImpl{
						Namespace: m.Namespace,
						Verb:      "get",
						Resource:  r,
					},
				},
				clienttesting.DeleteActionImpl{
					Name: m.Name,
					ActionImpl: clienttesting.ActionImpl{
						Namespace: m.Namespace,
						Verb:      "delete",
						Resource:  r,
					},
				},
				clienttesting.CreateActionImpl{
					ActionImpl: clienttesting.ActionImpl{
						Namespace: m.Namespace,
						Verb:      "create",
						Resource:  r,
					},
					Object: &corev1.Secret{
						ObjectMeta: m,
						Type:       corev1.SecretTypeOpaque,
						Data: map[string][]byte{
							"foo": []byte("bar"),
						},
					},
				},
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tc.existing...)
			got, changed, err := ApplySecret(context.TODO(), client.CoreV1(), events.NewInMemoryRecorder("test"), tc.required)
			if !reflect.DeepEqual(tc.err, err) {
				t.Errorf("expected error %v, got %v", tc.err, err)
				return
			}

			if !equality.Semantic.DeepEqual(tc.expected, got) {
				t.Errorf("objects don't match %s", cmp.Diff(tc.expected, got))
			}

			if tc.changed != changed {
				t.Errorf("expected changed %t, got %t", tc.changed, changed)
			}

			gotActions := client.Actions()
			if !equality.Semantic.DeepEqual(tc.actions, gotActions) {
				t.Errorf("actions don't match: %s", cmp.Diff(tc.actions, gotActions))
			}
		})
	}
}

func TestApplyNamespace(t *testing.T) {
	tests := []struct {
		name     string
		existing []runtime.Object
		input    *corev1.Namespace

		expectedModified bool
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name: "create",
			input: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Annotations: map[string]string{"something-": ""}},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "namespaces") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "namespaces") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				}
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Namespace)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "remove run-level if requested",
			existing: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"some-label": "labelval", "run-level": "1"}},
				},
			},
			input: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"run-level-": ""}},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "namespaces") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}

				if !actions[1].Matches("update", "namespaces") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"some-label": "labelval"}},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Namespace)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "don't report modified if the removed annotation is already not present",
			existing: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"some-label": "labelval"}},
				},
			},
			input: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"run-level-": ""}},
			},

			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "namespaces") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "add run-level if requested",
			existing: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"some-label": "labelval"}},
				},
			},
			input: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"run-level": "1"}},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "namespaces") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}

				if !actions[1].Matches("update", "namespaces") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"run-level": "1", "some-label": "labelval"}},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Namespace)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			_, actualModified, err := ApplyNamespace(context.TODO(), client.CoreV1(), events.NewInMemoryRecorder("test"), test.input)
			if err != nil {
				t.Fatal(err)
			}
			if test.expectedModified != actualModified {
				t.Errorf("expected %v, got %v", test.expectedModified, actualModified)
			}
			test.verifyActions(client.Actions(), t)
		})
	}
}

func TestDeepCopyAvoidance(t *testing.T) {
	tests := []struct {
		name             string
		existing         []runtime.Object
		input            *corev1.Namespace
		expectedModified bool
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name: "create",
			input: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "bar"}, ResourceVersion: "1"},
			},

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "namespaces") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "namespaces") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "bar"}, ResourceVersion: "1"},
				}
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Namespace)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "nothing should happen if neither the input or the resource being updated has changed, since the last update",
			existing: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "bar"}, ResourceVersion: "1"},
				},
			},
			input: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "bar"}},
			},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "namespaces") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "update, if existing has changed outside of our control since last update of resource",
			existing: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "new"}, ResourceVersion: "2"},
				},
			},
			input: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "bar"}},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "namespaces") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "namespaces") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "bar"}, ResourceVersion: "2"},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Namespace)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name: "update, if input has changed since last update of resource",
			existing: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "bar"}, ResourceVersion: "2"},
				},
			},
			input: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "new"}},
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "namespaces") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "namespaces") {
					t.Error(spew.Sdump(actions))
				}
				expected := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{"foo": "new"}, ResourceVersion: "2"},
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Namespace)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			cache := NewResourceCache()
			_, actualModified, err := ApplyNamespaceImproved(context.TODO(), client.CoreV1(), events.NewInMemoryRecorder("test"), test.input, cache)
			if err != nil {
				t.Fatal(err)
			}
			if test.expectedModified != actualModified {
				t.Errorf("expected %v, got %v", test.expectedModified, actualModified)
			}
			test.verifyActions(client.Actions(), t)
		})
	}
}

func TestSyncSecret(t *testing.T) {
	tt := []struct {
		name                        string
		sourceNamespace, sourceName string
		targetNamespace, targetName string
		ownerRefs                   []metav1.OwnerReference
		existingObjects             []runtime.Object
		expectedSecret              *corev1.Secret
		expectedChanged             bool
		expectedErr                 error
	}{
		{
			name:            "syncing existing secret succeeds when the target is missing",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{"foo": []byte("bar")},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "targetNamespace",
					Name:      "targetName",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"foo": []byte("bar")},
			},
			expectedChanged: true,
			expectedErr:     nil,
		},
		{
			name:            "syncing existing secret succeeds when the target is present and up to date",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{"foo": []byte("bar")},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "targetNamespace",
						Name:      "targetName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{"foo": []byte("bar")},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "targetNamespace",
					Name:      "targetName",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"foo": []byte("bar")},
			},
			expectedChanged: false,
			expectedErr:     nil,
		},
		{
			name:            "syncing existing secret succeeds when the target is present and needs update",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{"foo": []byte("bar2")},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "targetNamespace",
						Name:      "targetName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{"foo": []byte("bar1")},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "targetNamespace",
					Name:      "targetName",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"foo": []byte("bar2")},
			},
			expectedChanged: true,
			expectedErr:     nil,
		},
		{
			name:            "syncing missing source secret doesn't fail",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			ownerRefs:       nil,
			existingObjects: []runtime.Object{},
			expectedSecret:  nil,
			expectedChanged: false,
			expectedErr:     nil,
		},
		{
			name:            "syncing missing source secret removes pre-existing target",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "targetNamespace",
						Name:      "targetName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{"foo": []byte("bar1")},
				},
			},
			expectedSecret:  nil,
			expectedChanged: true,
			expectedErr:     nil,
		},
		{
			name:            "syncing service account token doesn't sync without the token being present",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeServiceAccountToken,
					Data: map[string][]byte{"foo": []byte("bar")},
				},
			},
			expectedSecret:  nil,
			expectedChanged: false,
			expectedErr:     fmt.Errorf("secret sourceNamespace/sourceName doesn't have a token yet"),
		},
		{
			name:            "syncing service account token strips \"managed\" annotations",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
						Annotations: map[string]string{
							corev1.ServiceAccountNameKey: "foo",
							corev1.ServiceAccountUIDKey:  "bar",
						},
					},
					Type: corev1.SecretTypeServiceAccountToken,
					Data: map[string][]byte{"token": []byte("top-secret")},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "targetNamespace",
					Name:      "targetName",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"token": []byte("top-secret")},
			},
			expectedChanged: true,
			expectedErr:     nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tc.existingObjects...)
			secret, changed, err := SyncSecret(context.TODO(), client.CoreV1(), events.NewInMemoryRecorder("test"), tc.sourceNamespace, tc.sourceName, tc.targetNamespace, tc.targetName, tc.ownerRefs)

			if !reflect.DeepEqual(err, tc.expectedErr) {
				t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				return
			}

			if !equality.Semantic.DeepEqual(secret, tc.expectedSecret) {
				t.Errorf("secrets differ: %s", cmp.Diff(tc.expectedSecret, secret))
			}

			if changed != tc.expectedChanged {
				t.Errorf("expected changed %t, got %t", tc.expectedChanged, changed)
			}
		})
	}
}

func TestSyncPartialSync(t *testing.T) {
	tt := []struct {
		name                        string
		sourceNamespace, sourceName string
		targetNamespace, targetName string
		syncedKeys                  sets.String
		ownerRefs                   []metav1.OwnerReference
		existingObjects             []runtime.Object
		expectedSecret              *corev1.Secret
		expectedChanged             bool
		expectedErr                 error
	}{
		{
			name:            "syncing existing secret succeeds when the target is missing when the synced keys are present",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			syncedKeys:      sets.NewString("foo", "qux"),
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"foo": []byte("bar"),
						"baz": []byte("bax"),
						"qux": []byte("mux"),
					},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "targetNamespace",
					Name:      "targetName",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"foo": []byte("bar"),
					"qux": []byte("mux"),
				},
			},
			expectedChanged: true,
			expectedErr:     nil,
		},
		{
			name:            "syncing existing secret when the target is missing does nothing when the synced keys are missing",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			syncedKeys:      sets.NewString("lol", "troll", "semaphore"),
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"foo": []byte("bar"),
						"baz": []byte("bax"),
						"qux": []byte("mux"),
					},
				},
			},
		},
		{
			name:            "syncing existing secret succeeds when the target is present and up to date",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			syncedKeys:      sets.NewString("foo", "baz"),
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"foo": []byte("bar"),
						"baz": []byte("bax"),
						"qux": []byte("mux"),
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "targetNamespace",
						Name:      "targetName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"foo": []byte("bar"),
						"baz": []byte("bax"),
					},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "targetNamespace",
					Name:      "targetName",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"baz": []byte("bax"),
					"foo": []byte("bar"),
				},
			},
			expectedChanged: false,
			expectedErr:     nil,
		},
		{
			name:            "syncing existing secret succeeds when the target is present and needs update",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			syncedKeys:      sets.NewString("foo", "qux", "troll", "semaphore"),
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"foo": []byte("bar2"),
						"baz": []byte("bax"),
						"qux": []byte("mux"),
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "targetNamespace",
						Name:      "targetName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"foo":   []byte("bar1"),
						"qux":   []byte("mux"),
						"troll": []byte("moll"),
						"lol":   []byte("poll"),
					},
				},
			},
			expectedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "targetNamespace",
					Name:      "targetName",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"foo": []byte("bar2"),
					"qux": []byte("mux"),
				},
			},
			expectedChanged: true,
			expectedErr:     nil,
		},
		{
			name:            "syncing missing source secret doesn't fail",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			syncedKeys:      sets.NewString("foo", "baz"),
			ownerRefs:       nil,
			existingObjects: []runtime.Object{},
			expectedSecret:  nil,
			expectedChanged: false,
			expectedErr:     nil,
		},
		{
			name:            "syncing service account token doesn't sync without the token being present",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			syncedKeys:      sets.NewString("foo"),
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeServiceAccountToken,
					Data: map[string][]byte{"foo": []byte("bar")},
				},
			},
			expectedSecret:  nil,
			expectedChanged: false,
			expectedErr:     fmt.Errorf("secret sourceNamespace/sourceName doesn't have a token yet"),
		},
		{
			name:            "syncing existing secret deletes the target when the source secret does not contain any synced keys",
			sourceNamespace: "sourceNamespace",
			sourceName:      "sourceName",
			targetNamespace: "targetNamespace",
			targetName:      "targetName",
			syncedKeys:      sets.NewString("troll", "semaphore"),
			ownerRefs:       nil,
			existingObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "sourceNamespace",
						Name:      "sourceName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"foo": []byte("bar2"),
						"baz": []byte("bax"),
						"qux": []byte("mux"),
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "targetNamespace",
						Name:      "targetName",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"troll": []byte("moll"),
					},
				},
			},
			expectedSecret:  nil,
			expectedChanged: true,
			expectedErr:     nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tc.existingObjects...)
			secret, changed, err := SyncPartialSecret(context.TODO(), client.CoreV1(), events.NewInMemoryRecorder("test"), tc.sourceNamespace, tc.sourceName, tc.targetNamespace, tc.targetName, tc.syncedKeys, tc.ownerRefs)

			if !reflect.DeepEqual(err, tc.expectedErr) {
				t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				return
			}

			if !equality.Semantic.DeepEqual(secret, tc.expectedSecret) {
				t.Errorf("secrets differ: %s", cmp.Diff(tc.expectedSecret, secret))
			}

			if changed != tc.expectedChanged {
				t.Errorf("expected changed %t, got %t", tc.expectedChanged, changed)
			}
		})
	}
}

func withSpecHash(srv *corev1.Service) *corev1.Service {
	ret := srv.DeepCopy()
	SetSpecHashAnnotation(&ret.ObjectMeta, ret.Spec)
	return ret
}

func TestApplyService(t *testing.T) {
	srv1Port := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Name:      "srv",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "port1",
					Port: 80,
				},
			},
			Type: corev1.ServiceTypeLoadBalancer,
		},
	}

	// srv1Port where user changed type without changing spec hash
	userChangedSrv1Type := withSpecHash(srv1Port)
	userChangedSrv1Type.Spec.Type = corev1.ServiceTypeClusterIP
	// srv1Port where user changed an untracked field without changing spec hash
	userChangedSrv1Untracked := withSpecHash(srv1Port)
	userChangedSrv1Untracked.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeCluster

	srv2Ports := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Name:      "srv",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "port1",
					Port: 80,
				},
				{
					Name: "port2",
					Port: 443,
				},
			},
			Type: corev1.ServiceTypeLoadBalancer,
		},
	}

	tt := []struct {
		name             string
		existingObjects  []runtime.Object
		input            *corev1.Service
		expectedModified bool
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name:             "create when missing",
			existingObjects:  nil,
			input:            srv1Port,
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "services") || actions[0].(clienttesting.GetAction).GetName() != "srv" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "services") {
					t.Error(spew.Sdump(actions))
				}

				expected := withSpecHash(srv1Port)
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Service)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name:             "update when caller wants to change spec",
			existingObjects:  []runtime.Object{withSpecHash(srv1Port)},
			input:            srv2Ports,
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "services") || actions[0].(clienttesting.GetAction).GetName() != "srv" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "services") {
					t.Error(spew.Sdump(actions))
				}

				expected := withSpecHash(srv2Ports)
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Service)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name:             "no update when nothing changes",
			existingObjects:  []runtime.Object{withSpecHash(srv1Port)},
			input:            srv1Port,
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "services") || actions[0].(clienttesting.GetAction).GetName() != "srv" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name:             "overwrite when user changes type",
			existingObjects:  []runtime.Object{userChangedSrv1Type},
			input:            withSpecHash(srv1Port),
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "services") || actions[0].(clienttesting.GetAction).GetName() != "srv" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "services") {
					t.Error(spew.Sdump(actions))
				}

				expected := withSpecHash(srv1Port)
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Service)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name:             "no overwrite when user changes an untracked field",
			existingObjects:  []runtime.Object{userChangedSrv1Untracked},
			input:            withSpecHash(srv1Port),
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "services") || actions[0].(clienttesting.GetAction).GetName() != "srv" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existingObjects...)
			_, actualModified, err := ApplyService(context.TODO(), client.CoreV1(), events.NewInMemoryRecorder("test"), test.input)
			if err != nil {
				t.Fatal(err)
			}
			if test.expectedModified != actualModified {
				t.Errorf("expected %v, got %v", test.expectedModified, actualModified)
			}
			test.verifyActions(client.Actions(), t)
		})
	}
}
