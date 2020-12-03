package resourceapply

import (
	"fmt"
	"strings"
	"testing"

	ktesting "k8s.io/client-go/testing"

	"github.com/openshift/client-go/config/clientset/versioned/scheme"
	"github.com/openshift/library-go/pkg/operator/events"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

func init() {
	utilruntime.Must(admissionregistrationv1.AddToScheme(scheme.Scheme))
}

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
		// Simulate server-side generation increase on update
		disableGeneration  bool
		observedGeneration int64
		expectedGeneration int64
		existing           func() *admissionregistrationv1.MutatingWebhookConfiguration
		input              func() *admissionregistrationv1.MutatingWebhookConfiguration
		checkUpdated       func(*admissionregistrationv1.MutatingWebhookConfiguration) error
		expectedEvents     []string
	}{
		{
			name:               "Should successfully create webhook",
			expectModified:     true,
			expectedGeneration: 1,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			expectedEvents: []string{createEvent},
		},
		{
			name:           "Should update webhook when changed",
			expectModified: true,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks, admissionregistrationv1.MutatingWebhook{
					Name: "test",
				})
				return hook
			},
			observedGeneration: 1,
			expectedGeneration: 3,
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook has changed externally since last observation
				hook.SetGeneration(2)
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
			observedGeneration: 1,
			expectedGeneration: 1,
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook is unchanged generation-wise
				hook.SetGeneration(1)
				return hook
			},
		},
		{
			name:               "Should create webhook and attempt an update when generation check is disabled, but report changes only once",
			expectModified:     true,
			disableGeneration:  true,
			expectedGeneration: 1,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			expectedEvents: []string{createEvent, updateEvent},
		},
		{
			name:           "Should attempt to update resource twice when generation check is disabled but report changes only once",
			expectModified: true,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			// Generation check is disabled, or this is the first apply
			disableGeneration:  true,
			observedGeneration: 0,
			expectedGeneration: 2,
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook is unchanged generation-wise
				hook.SetGeneration(1)
				return hook
			},
			expectedEvents: []string{updateEvent, updateEvent},
		},
		{
			name:           "Should update webhook, but preserve caBundle field if it is not set",
			expectModified: true,
			input: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks,
					admissionregistrationv1.MutatingWebhook{Name: "test"},
					admissionregistrationv1.MutatingWebhook{Name: "second"})
				return hook
			},
			observedGeneration: 1,
			expectedGeneration: 3,
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook has changed externally since last observation
				hook.SetGeneration(2)
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
				hook.Webhooks = append(hook.Webhooks,
					admissionregistrationv1.MutatingWebhook{
						Name:         "test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: []byte("test")},
					},
					admissionregistrationv1.MutatingWebhook{Name: "second"})
				return hook
			},
			observedGeneration: 1,
			expectedGeneration: 3,
			existing: func() *admissionregistrationv1.MutatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook has changed externally since last observation
				hook.SetGeneration(2)
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

			testApply := func(expectedGeneration int64, expectModify bool) {
				updatedHook, modified, err := ApplyMutatingWebhookConfiguration(
					client.AdmissionregistrationV1(),
					recorder, test.input(), expectedGeneration)
				if err != nil {
					t.Fatal(err)
				}
				if expectModify != modified {
					t.Errorf("expected modified to be equal %v, got %v: %#v", expectModify, modified, updatedHook)
				}
				if expectedGeneration != 0 && expectedGeneration != updatedHook.GetGeneration() {
					t.Errorf("expected generation to be %v, got %v, %#v", expectedGeneration, updatedHook.GetGeneration(), updatedHook)
				}

				if test.checkUpdated != nil {
					if err = test.checkUpdated(updatedHook); err != nil {
						t.Errorf("Expected modification: %v", err)
					}
				}
			}

			testApply(test.expectedGeneration, test.expectModified)

			// Second modification with generation tracking
			testApply(test.expectedGeneration, false)

			// Disabled generation tracking
			if test.disableGeneration {
				testApply(0, false)
			}

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
		// Simulate server-side generation increase on update
		disableGeneration  bool
		observedGeneration int64
		expectedGeneration int64
		existing           func() *admissionregistrationv1.ValidatingWebhookConfiguration
		input              func() *admissionregistrationv1.ValidatingWebhookConfiguration
		checkUpdated       func(*admissionregistrationv1.ValidatingWebhookConfiguration) error
		expectedEvents     []string
	}{
		{
			name:               "Should successfully create webhook",
			expectModified:     true,
			expectedGeneration: 1,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			expectedEvents: []string{createEvent},
		},
		{
			name:           "Should update webhook when changed",
			expectModified: true,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks, admissionregistrationv1.ValidatingWebhook{
					Name: "test",
				})
				return hook
			},
			observedGeneration: 1,
			expectedGeneration: 3,
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook has changed externally since last observation
				hook.SetGeneration(2)
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
			observedGeneration: 1,
			expectedGeneration: 1,
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook is unchanged generation-wise
				hook.SetGeneration(1)
				return hook
			},
		},
		{
			name:               "Should create webhook and attempt an update when generation check is disabled, but report changes only once",
			expectModified:     true,
			disableGeneration:  true,
			expectedGeneration: 1,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			expectedEvents: []string{createEvent, updateEvent},
		},
		{
			name:           "Should attempt to update resource twice when generation check is disabled but report changes only once",
			expectModified: true,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				return defaultHook.DeepCopy()
			},
			// Generation check is disabled, or this is the first apply
			disableGeneration:  true,
			observedGeneration: 0,
			expectedGeneration: 2,
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook is unchanged generation-wise
				hook.SetGeneration(1)
				return hook
			},
			expectedEvents: []string{updateEvent, updateEvent},
		},
		{
			name:           "Should update webhook, but preserve caBundle field if it is not set",
			expectModified: true,
			input: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				hook.Webhooks = append(hook.Webhooks,
					admissionregistrationv1.ValidatingWebhook{Name: "test"},
					admissionregistrationv1.ValidatingWebhook{Name: "second"})
				return hook
			},
			observedGeneration: 1,
			expectedGeneration: 3,
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook has changed externally since last observation
				hook.SetGeneration(2)
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
				hook.Webhooks = append(hook.Webhooks,
					admissionregistrationv1.ValidatingWebhook{
						Name:         "test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: []byte("test")},
					},
					admissionregistrationv1.ValidatingWebhook{Name: "second"})
				return hook
			},
			observedGeneration: 1,
			expectedGeneration: 3,
			existing: func() *admissionregistrationv1.ValidatingWebhookConfiguration {
				hook := defaultHook.DeepCopy()
				// Webhook has changed externally since last observation
				hook.SetGeneration(2)
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

			testApply := func(expectedGeneration int64, expectModify bool) {
				updatedHook, modified, err := ApplyValidatingWebhookConfiguration(
					client.AdmissionregistrationV1(),
					recorder, test.input(), expectedGeneration)
				if err != nil {
					t.Fatal(err)
				}
				if expectModify != modified {
					t.Errorf("expected modified to be equal %v, got %v: %#v", expectModify, modified, updatedHook)
				}
				if expectedGeneration != 0 && expectedGeneration != updatedHook.GetGeneration() {
					t.Errorf("expected generation to be %v, got %v, %#v", expectedGeneration, updatedHook.GetGeneration(), updatedHook)
				}

				if test.checkUpdated != nil {
					if err = test.checkUpdated(updatedHook); err != nil {
						t.Errorf("Expected modification: %v", err)
					}
				}
			}

			testApply(test.expectedGeneration, test.expectModified)

			// Second modification with generation tracking
			testApply(test.expectedGeneration, false)

			// Disabled generation tracking
			if test.disableGeneration {
				testApply(0, false)
			}

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
