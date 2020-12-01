package resourceapply

import (
	"testing"

	"github.com/davecgh/go-spew/spew"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/openshift/library-go/pkg/operator/events"
)

func TestApplyValidatingWebhookConfiguration(t *testing.T) {
	tests := []struct {
		name            string
		existing        []runtime.Object
		input           *admissionv1.ValidatingWebhookConfiguration
		inputGeneration int64

		expectedModified bool
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name:  "create",
			input: validatingwebhook("webhook1"),

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "validatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "validatingwebhookconfigurations") {
					t.Error(spew.Sdump(actions))
				}
				expected := validatingwebhookWithSpecHash("webhook1")

				actual := actions[1].(clienttesting.CreateAction).GetObject().(*admissionv1.ValidatingWebhookConfiguration)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name:  "update webhooks",
			input: validatingwebhook("webhook1"),
			existing: []runtime.Object{
				validatingwebhookWithSpecHash("webhook2"),
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "validatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "validatingwebhookconfigurations") {
					t.Error(spew.Sdump(actions))
				}
				expected := validatingwebhookWithSpecHash("webhook1")
				actual := actions[1].(clienttesting.UpdateActionImpl).GetObject().(*admissionv1.ValidatingWebhookConfiguration)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name:             "no update",
			input:            validatingwebhook("webhook1"),
			existing:         []runtime.Object{validatingwebhookWithSpecHash("webhook1")},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "validatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name:            "update by different generation",
			input:           validatingwebhook("webhook1"),
			inputGeneration: 0,
			existing: []runtime.Object{
				func() *admissionv1.ValidatingWebhookConfiguration {
					hook := validatingwebhookWithSpecHash("webhook1")
					hook.Generation = 1
					return hook
				}(),
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "validatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "validatingwebhookconfigurations") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name:            "update with default CAbundle set",
			input:           validatingwebhook("webhook1"),
			inputGeneration: 0,
			existing: []runtime.Object{
				func() *admissionv1.ValidatingWebhookConfiguration {
					hook := validatingwebhookWithSpecHash("webhook1")
					hook.Webhooks[0].ClientConfig.CABundle = []byte("test")
					return hook
				}(),
			},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "validatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			_, actualModified, err := ApplyValidatingWebhookConfiguration(client.AdmissionregistrationV1(), events.NewInMemoryRecorder("test"), test.input, test.inputGeneration)
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

func TestApplyMutatingWebhookConfiguration(t *testing.T) {
	tests := []struct {
		name            string
		existing        []runtime.Object
		input           *admissionv1.MutatingWebhookConfiguration
		inputGeneration int64

		expectedModified bool
		verifyActions    func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name:  "create",
			input: mutatingwebhook("webhook1"),

			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "mutatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "mutatingwebhookconfigurations") {
					t.Error(spew.Sdump(actions))
				}
				expected := mutatingwebhookWithSpecHash("webhook1")
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*admissionv1.MutatingWebhookConfiguration)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name:  "update webhooks",
			input: mutatingwebhook("webhook1"),
			existing: []runtime.Object{
				mutatingwebhookWithSpecHash("webhook2"),
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "mutatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "mutatingwebhookconfigurations") {
					t.Error(spew.Sdump(actions))
				}
				expected := mutatingwebhookWithSpecHash("webhook1")
				actual := actions[1].(clienttesting.UpdateActionImpl).GetObject().(*admissionv1.MutatingWebhookConfiguration)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(JSONPatchNoError(expected, actual))
				}
			},
		},
		{
			name:             "no update",
			input:            mutatingwebhook("webhook1"),
			existing:         []runtime.Object{mutatingwebhookWithSpecHash("webhook1")},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "mutatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name:            "update with differernt generation",
			input:           mutatingwebhook("webhook1"),
			inputGeneration: 0,
			existing: []runtime.Object{
				func() *admissionv1.MutatingWebhookConfiguration {
					hook := mutatingwebhookWithSpecHash("webhook1")
					hook.Generation = 1
					return hook
				}(),
			},
			expectedModified: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "mutatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("update", "mutatingwebhookconfigurations") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name:            "update with default CAbundle set",
			input:           mutatingwebhook("webhook1"),
			inputGeneration: 0,
			existing: []runtime.Object{
				func() *admissionv1.MutatingWebhookConfiguration {
					hook := mutatingwebhookWithSpecHash("webhook1")
					hook.Webhooks[0].ClientConfig.CABundle = []byte("test")
					return hook
				}(),
			},
			expectedModified: false,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "mutatingwebhookconfigurations") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			_, actualModified, err := ApplyMutatingWebhookConfiguration(client.AdmissionregistrationV1(), events.NewInMemoryRecorder("test"), test.input, test.inputGeneration)
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

func validatingwebhook(webhookName string) *admissionv1.ValidatingWebhookConfiguration {
	return &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "foo"},
		Webhooks: []admissionv1.ValidatingWebhook{
			{
				Name: webhookName,
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{
						Name:      "foo",
						Namespace: "bar",
					},
				},
			},
		},
	}
}

func validatingwebhookWithSpecHash(webhookName string) *admissionv1.ValidatingWebhookConfiguration {
	hook := validatingwebhook(webhookName)
	SetSpecHashAnnotation(&hook.ObjectMeta, hook.Webhooks)
	return hook
}

func mutatingwebhook(webhookName string) *admissionv1.MutatingWebhookConfiguration {
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "foo"},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name: webhookName,
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{
						Name:      "foo",
						Namespace: "bar",
					},
				},
			},
		},
	}
}

func mutatingwebhookWithSpecHash(webhookName string) *admissionv1.MutatingWebhookConfiguration {
	hook := mutatingwebhook(webhookName)
	SetSpecHashAnnotation(&hook.ObjectMeta, hook.Webhooks)
	return hook
}
