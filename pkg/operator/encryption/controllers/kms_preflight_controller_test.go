package controllers

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"

	"github.com/openshift/library-go/pkg/controller/factory"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestKMSPreflightController(t *testing.T) {
	scenarios := []struct {
		name              string
		apiServerObjects  []runtime.Object
		preconditionsMet  bool
		expectedError     bool
		expectedCondition *operatorv1.OperatorCondition
	}{
		{
			name:             "preconditions not met, clears degraded",
			apiServerObjects: []runtime.Object{&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}},
			preconditionsMet: false,
			expectedError:    false,
			expectedCondition: &operatorv1.OperatorCondition{
				Type:   "EncryptionKMSPreflightControllerDegraded",
				Status: "False",
			},
		},
		{
			name:             "preconditions met, sync returns error from stub",
			apiServerObjects: []runtime.Object{&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}},
			preconditionsMet: true,
			expectedError:    true,
			expectedCondition: &operatorv1.OperatorCondition{
				Type:    "EncryptionKMSPreflightControllerDegraded",
				Status:  "True",
				Reason:  "Error",
				Message: "implement me",
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						Conditions: []operatorv1.OperatorCondition{
							{
								Type:   "EncryptionKMSPreflightControllerDegraded",
								Status: "False",
							},
						},
					},
				},
				nil,
				nil,
			)

			fakeKubeClient := fake.NewSimpleClientset()
			eventRecorder := events.NewRecorder(fakeKubeClient.CoreV1().Events("test"), "test-kmsPreflightController", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))

			fakeConfigClient := configv1clientfake.NewSimpleClientset(scenario.apiServerObjects...)
			fakeApiServerClient := fakeConfigClient.ConfigV1().APIServers()
			fakeApiServerInformer := configv1informers.NewSharedInformerFactory(fakeConfigClient, time.Minute).Config().V1().APIServers()

			preconditionsFn := func() (bool, error) { return scenario.preconditionsMet, nil }
			provider := newTestProvider([]schema.GroupResource{{Group: "", Resource: "secrets"}})

			target := NewKMSPreflightController(
				"test",
				provider,
				preconditionsFn,
				fakeOperatorClient,
				fakeApiServerClient,
				fakeApiServerInformer,
				eventRecorder,
			)

			err := target.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))

			if scenario.expectedError && err == nil {
				t.Fatal("expected error but got nil")
			}
			if !scenario.expectedError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if scenario.expectedCondition != nil {
				encryptiontesting.ValidateOperatorClientConditions(t, fakeOperatorClient, []operatorv1.OperatorCondition{*scenario.expectedCondition})
			}
		})
	}
}
