package resourceapply

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/openshift/library-go/pkg/operator/events"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestApplyMutatingConfiguration(t *testing.T) {
	defaultHook := &admissionregistrationv1.MutatingWebhookConfiguration{}
	defaultHook.SetName("test")
	createEvent := "MutatingWebhookConfigurationCreated"
	updateEvent := "MutatingWebhookConfigurationUpdated"

	injectGeneration := func(generation int64) ktesting.ReactionFunc {
		return func(action ktesting.Action) (bool, runtime.Object, error) {
			actual, _ := action.(ktesting.CreateAction)
			webhookConfiguration, _ := actual.GetObject().(*admissionregistrationv1.MutatingWebhookConfiguration)
			webhookConfiguration.SetGeneration(generation)
			return false, webhookConfiguration, nil
		}
	}

	tests := []struct {
		name           string
		expectModified bool
		existing       func() *admissionregistrationv1.MutatingWebhookConfiguration
		input          func() *admissionregistrationv1.MutatingWebhookConfiguration
		checkUpdated   func(*admissionregistrationv1.MutatingWebhookConfiguration) error
		expectedEvents []string
	}{
		{
			name:           "Should successfully create webhook",
			expectModified: true,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			expectedEvents: []string{createEvent},
		},
		{
			name:           "Should update webhook when annotation changed",
			expectModified: true,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Annotations = map[string]string{"updated-annotation": "updated-annotation"}
				return hook
			},
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				return hook
			},
			expectedEvents: []string{updateEvent},
		},
		{
			name:           "Should update webhook when changed",
			expectModified: true,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				return hook
			},
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks, admissionregistrationv1.MutatingWebhook{
					Name: "unexpected",
				})
				return hook
			},
			expectedEvents: []string{updateEvent},
		},
		{
			name:           "Should not update webhook when is unchanged",
			expectModified: false,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
		},
		{
			name:           "Should update webhook, but preserve caBundle field if it is not set",
			expectModified: true,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Annotations = map[string]string{"updated-annotation": "updated-annotation"}
				hook.Webhooks = append(hook.Webhooks,
					admissionregistrationv1.MutatingWebhook{Name: "test"},
					admissionregistrationv1.MutatingWebhook{Name: "second"})
				return hook
			},
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks, admissionregistrationv1.MutatingWebhook{
					Name: "test",
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						CABundle: []byte("test"),
					},
					AdmissionReviewVersions: []string{"v1beta1"},
				})
				return hook
			},
			checkUpdated: func(hook *admissionregistrationv1.MutatingWebhookConfiguration) error {
				if len(hook.Webhooks) != 2 {
					return fmt.Errorf("Expected to find both webhooks, got: %+v", hook.Webhooks)
				}
				for _, webhook := range hook.Webhooks {
					if string(webhook.ClientConfig.CABundle) == "test" {
						return nil
					}
				}
				return fmt.Errorf("Expected to find webhook with unchanged clientConfig.caBundle injection == 'test', got: %#v", hook)
			},
			expectedEvents: []string{updateEvent},
		},
		{
			name:           "Should update webhook, and force caBundle field if is set",
			expectModified: true,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Annotations = map[string]string{"updated-annotation": "updated-annotation"}
				hook.Webhooks = append(hook.Webhooks,
					admissionregistrationv1.MutatingWebhook{
						Name:         "test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: []byte("test")},
					},
					admissionregistrationv1.MutatingWebhook{Name: "second"})
				return hook
			},
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks, admissionregistrationv1.MutatingWebhook{
					Name:                    "test",
					AdmissionReviewVersions: []string{"v1beta1"},
				})
				return hook
			},
			checkUpdated: func(hook *admissionregistrationv1.MutatingWebhookConfiguration) error {
				if len(hook.Webhooks) != 2 {
					return fmt.Errorf("Expected to find both webhooks, got: %+v", hook.Webhooks)
				}
				for _, webhook := range hook.Webhooks {
					if string(webhook.ClientConfig.CABundle) == "test" {
						return nil
					}
				}
				return fmt.Errorf("Expected to find webhook with unchanged clientConfig.caBundle injection == 'test', got: %#v", hook)
			},
			expectedEvents: []string{updateEvent},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			existingHooks := []runtime.Object{}
			if test.existing != nil {
				existingHooks = append(existingHooks, test.existing())
			}
			client := fake.NewSimpleClientset(existingHooks...)

			// Simulate server-side generation increase
			client.PrependReactor("create", "*", injectGeneration(1))
			if test.existing != nil {
				client.PrependReactor("update", "*", injectGeneration(test.existing().GetGeneration()+1))
			}
			recorder := events.NewInMemoryRecorder("test")

			testApply := func(expectModify bool) {
				updatedHook, modified, err := ApplyMutatingWebhookConfigurationImproved(
					context.TODO(),
					client.AdmissionregistrationV1(),
					recorder, test.input(), noCache)
				if err != nil {
					t.Fatal(err)
				}
				if expectModify != modified {
					t.Errorf("expected modified to be equal %v, got %v: %#v", expectModify, modified, updatedHook)
				}

				if test.checkUpdated != nil {
					if err = test.checkUpdated(updatedHook); err != nil {
						t.Errorf("Expected modification: %v", err)
					}
				}
			}

			testApply(test.expectModified)
			assertEvents(t, test.name, test.expectedEvents, recorder.Events())
		})
	}
}

func TestApplyValidatingConfiguration(t *testing.T) {
	defaultHook := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	defaultHook.SetName("test")
	createEvent := "ValidatingWebhookConfigurationCreated"
	updateEvent := "ValidatingWebhookConfigurationUpdated"

	injectGeneration := func(generation int64) ktesting.ReactionFunc {
		return func(action ktesting.Action) (bool, runtime.Object, error) {
			actual, _ := action.(ktesting.CreateAction)
			webhookConfiguration, _ := actual.GetObject().(*admissionregistrationv1.ValidatingWebhookConfiguration)
			webhookConfiguration.SetGeneration(generation)
			return false, webhookConfiguration, nil
		}
	}

	tests := []struct {
		name           string
		expectModified bool
		existing       func() *admissionregistrationv1.ValidatingWebhookConfiguration
		input          func() *admissionregistrationv1.ValidatingWebhookConfiguration
		checkUpdated   func(*admissionregistrationv1.ValidatingWebhookConfiguration) error
		expectedEvents []string
	}{
		{
			name:           "Should successfully create webhook",
			expectModified: true,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			expectedEvents: []string{createEvent},
		},
		{
			name:           "Should update webhook when annotation changed",
			expectModified: true,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Annotations = map[string]string{"updated-annotation": "updated-annotation"}
				return hook
			},
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				return hook
			},
			expectedEvents: []string{updateEvent},
		},
		{
			name:           "Should update webhook when changed",
			expectModified: true,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				return hook
			},
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks, admissionregistrationv1.ValidatingWebhook{
					Name: "unexpected",
				})
				return hook
			},
			expectedEvents: []string{updateEvent},
		},
		{
			name:           "Should not update webhook when is unchanged",
			expectModified: false,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				return defaultHook.DeepCopy()

			},
		},
		{
			name:           "Should update webhook, but preserve caBundle field if it is not set",
			expectModified: true,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Annotations = map[string]string{"updated-annotation": "updated-annotation"}
				hook.Webhooks = append(hook.Webhooks,
					admissionregistrationv1.ValidatingWebhook{Name: "test"},
					admissionregistrationv1.ValidatingWebhook{Name: "second"})
				return hook
			},
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks, admissionregistrationv1.ValidatingWebhook{
					Name: "test",
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						CABundle: []byte("test"),
					},
					AdmissionReviewVersions: []string{"v1beta1"},
				})
				return hook
			},
			checkUpdated: func(hook *admissionregistrationv1.ValidatingWebhookConfiguration) error {
				if len(hook.Webhooks) != 2 {
					return fmt.Errorf("Expected to find both webhooks, got: %+v", hook.Webhooks)
				}
				for _, webhook := range hook.Webhooks {
					if string(webhook.ClientConfig.CABundle) == "test" {
						return nil
					}
				}
				return fmt.Errorf("Expected to find webhook with unchanged clientConfig.caBundle injection == 'test', got: %#v", hook)
			},
			expectedEvents: []string{updateEvent},
		},
		{
			name:           "Should update webhook, and force caBundle field if is set",
			expectModified: true,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Annotations = map[string]string{"updated-annotation": "updated-annotation"}
				hook.Webhooks = append(hook.Webhooks,
					admissionregistrationv1.ValidatingWebhook{
						Name:         "test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: []byte("test")},
					},
					admissionregistrationv1.ValidatingWebhook{Name: "second"})
				return hook
			},
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks, admissionregistrationv1.ValidatingWebhook{
					Name:                    "test",
					AdmissionReviewVersions: []string{"v1beta1"},
				})
				return hook
			},
			checkUpdated: func(hook *admissionregistrationv1.ValidatingWebhookConfiguration) error {
				if len(hook.Webhooks) != 2 {
					return fmt.Errorf("Expected to find both webhooks, got: %+v", hook.Webhooks)
				}
				for _, webhook := range hook.Webhooks {
					if string(webhook.ClientConfig.CABundle) == "test" {
						return nil
					}
				}
				return fmt.Errorf("Expected to find webhook with unchanged clientConfig.caBundle injection == 'test', got: %#v", hook)
			},
			expectedEvents: []string{updateEvent},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			existingHooks := []runtime.Object{}
			if test.existing != nil {
				existingHooks = append(existingHooks, test.existing())
			}
			client := fake.NewSimpleClientset(existingHooks...)

			// Simulate server-side generation increase
			client.PrependReactor("create", "*", injectGeneration(1))
			if test.existing != nil {
				client.PrependReactor("update", "*", injectGeneration(test.existing().GetGeneration()+1))
			}
			recorder := events.NewInMemoryRecorder("test")

			testApply := func(expectModify bool) {
				updatedHook, modified, err := ApplyValidatingWebhookConfigurationImproved(
					context.TODO(),
					client.AdmissionregistrationV1(),
					recorder, test.input(), noCache)
				if err != nil {
					t.Fatal(err)
				}
				if expectModify != modified {
					t.Errorf("expected modified to be equal %v, got %v: %#v", expectModify, modified, updatedHook)
				}

				if test.checkUpdated != nil {
					if err = test.checkUpdated(updatedHook); err != nil {
						t.Errorf("Expected modification: %v", err)
					}
				}
			}

			testApply(test.expectModified)
			assertEvents(t, test.name, test.expectedEvents, recorder.Events())
		})
	}
}

func TestDeleteValidatingConfiguration(t *testing.T) {
	defaultHook := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	defaultHook.SetName("test")
	deleteEvent := "ValidatingWebhookConfigurationDeleted"

	tests := []struct {
		name           string
		expectModified bool
		existing       func() *admissionregistrationv1.ValidatingWebhookConfiguration
		input          func() *admissionregistrationv1.ValidatingWebhookConfiguration
		expectedEvents []string
	}{
		{
			name:           "Should delete webhook if it exists",
			expectModified: true,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				return hook
			},
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				return hook
			},
			expectedEvents: []string{deleteEvent},
		},
		{
			name:           "Should do nothing if webhook does not exist",
			expectModified: false,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				return hook
			},
			expectedEvents: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			existingHooks := []runtime.Object{}
			if test.existing != nil {
				existingHooks = append(existingHooks, test.existing())
			}
			client := fake.NewSimpleClientset(existingHooks...)
			recorder := events.NewInMemoryRecorder("test")

			testApply := func(expectModify bool) {
				updatedHook, modified, err := DeleteValidatingWebhookConfiguration(
					context.TODO(),
					client.AdmissionregistrationV1(),
					recorder, test.input())
				if err != nil {
					t.Fatal(err)
				}
				if expectModify != modified {
					t.Errorf("expected modified to be equal %v, got %v: %#v", expectModify, modified, updatedHook)
				}
			}

			testApply(test.expectModified)
			assertEvents(t, test.name, test.expectedEvents, recorder.Events())
		})
	}
}

func TestApplyValidatingAdmissionPolicyConfiguration(t *testing.T) {
	defaultPolicy := &admissionregistrationv1beta1.ValidatingAdmissionPolicy{}
	defaultPolicy.SetName("test")
	createEvent := "ValidatingAdmissionPolicyCreated"
	updateEvent := "ValidatingAdmissionPolicyUpdated"

	injectGeneration := func(generation int64) ktesting.ReactionFunc {
		return func(action ktesting.Action) (bool, runtime.Object, error) {
			actual, _ := action.(ktesting.CreateAction)
			policy, _ := actual.GetObject().(*admissionregistrationv1beta1.ValidatingAdmissionPolicy)
			policy.SetGeneration(generation)
			return false, policy, nil
		}
	}

	tests := []struct {
		name           string
		expectModified bool
		existing       func() *admissionregistrationv1beta1.ValidatingAdmissionPolicy
		input          func() *admissionregistrationv1beta1.ValidatingAdmissionPolicy
		checkUpdated   func(*admissionregistrationv1beta1.ValidatingAdmissionPolicy) error
		expectedEvents []string
	}{
		{
			name:           "Should successfully create policy",
			expectModified: true,
			input: func() *admissionregistrationv1beta1.ValidatingAdmissionPolicy {
				return defaultPolicy.DeepCopy()
			},
			expectedEvents: []string{createEvent},
		},
		{
			name:           "Should update policy when annotation changed",
			expectModified: true,
			input: func() *admissionregistrationv1beta1.ValidatingAdmissionPolicy {
				policy := defaultPolicy.DeepCopy()
				policy.Annotations = map[string]string{"updated-annotation": "updated-annotation"}
				return policy
			},
			existing: func() *admissionregistrationv1beta1.ValidatingAdmissionPolicy {
				policy := defaultPolicy.DeepCopy()
				return policy
			},
			expectedEvents: []string{updateEvent},
		},
		{
			name:           "Should update policy when changed",
			expectModified: true,
			input: func() *admissionregistrationv1beta1.ValidatingAdmissionPolicy {
				policy := defaultPolicy.DeepCopy()
				return policy
			},
			existing: func() *admissionregistrationv1beta1.ValidatingAdmissionPolicy {
				policy := defaultPolicy.DeepCopy()
				policy.Spec.MatchConditions = append(policy.Spec.MatchConditions, admissionregistrationv1beta1.MatchCondition{
					Name:       "unexpected",
					Expression: "unexpected",
				})
				return policy
			},
			expectedEvents: []string{updateEvent},
		},
		{
			name:           "Should not update policy when is unchanged",
			expectModified: false,
			input: func() *admissionregistrationv1beta1.ValidatingAdmissionPolicy {
				return defaultPolicy.DeepCopy()
			},
			existing: func() *admissionregistrationv1beta1.ValidatingAdmissionPolicy {
				return defaultPolicy.DeepCopy()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			existingHooks := []runtime.Object{}
			if test.existing != nil {
				existingHooks = append(existingHooks, test.existing())
			}
			client := fake.NewSimpleClientset(existingHooks...)

			// Simulate server-side generation increase
			client.PrependReactor("create", "*", injectGeneration(1))
			if test.existing != nil {
				client.PrependReactor("update", "*", injectGeneration(test.existing().GetGeneration()+1))
			}
			recorder := events.NewInMemoryRecorder("test")

			testApply := func(expectModify bool) {
				updatedPolicy, modified, err := ApplyValidatingAdmissionPolicyV1beta1(
					context.TODO(),
					client.AdmissionregistrationV1beta1(),
					recorder, test.input(), noCache)
				if err != nil {
					t.Fatal(err)
				}
				if expectModify != modified {
					t.Errorf("expected modified to be equal %v, got %v: %#v", expectModify, modified, updatedPolicy)
				}

				if test.checkUpdated != nil {
					if err = test.checkUpdated(updatedPolicy); err != nil {
						t.Errorf("Expected modification: %v", err)
					}
				}
			}

			testApply(test.expectModified)
			assertEvents(t, test.name, test.expectedEvents, recorder.Events())
		})
	}
}

func assertEvents(t *testing.T, testCase string, expectedReasons []string, events []*corev1.Event) {
	if len(expectedReasons) != len(events) {
		t.Errorf(
			"Test case: %s. Number of expected events (%v) differs from number of real events (%v)",
			testCase,
			len(expectedReasons),
			len(events),
		)
	} else {
		for i, event := range expectedReasons {
			if !strings.EqualFold(event, events[i].Reason) {
				t.Errorf("Test case: %s. Expected %v event, got: %v", testCase, event, events[i].Reason)
			}
		}
	}
}
