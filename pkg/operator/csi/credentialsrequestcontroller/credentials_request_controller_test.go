package credentialsrequestcontroller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"

	opv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	operandName                = "test-csi-driver"
	operandNamespace           = "test-csi-driver-namespace"
	controllerName             = "TestController"
	credentialsRequestKind     = "CredentialsRequest"
	credentialRequestNamespace = "openshift-cloud-credential-operator"
)

var (
	conditionTrue        = opv1.ConditionTrue
	conditionFalse       = opv1.ConditionFalse
	availableCondition   = controllerName + opv1.OperatorStatusTypeAvailable
	progressingCondition = controllerName + opv1.OperatorStatusTypeProgressing
)

type testCase struct {
	name                         string
	manifest                     []byte
	inputSecretProvisioned       bool
	expectedAvailableCondition   *opv1.ConditionStatus
	expectedProgressingCondition *opv1.ConditionStatus
	expectedFailingStatus        bool
}

func TestSync(t *testing.T) {
	tests := []testCase{
		{
			name:                         "Secret provisioned by cloud-credential-operator, healthy conditions",
			manifest:                     makeFakeManifest(operandName, credentialRequestNamespace, operandNamespace),
			inputSecretProvisioned:       true,
			expectedAvailableCondition:   &conditionTrue,
			expectedProgressingCondition: &conditionFalse,
			expectedFailingStatus:        false,
		},
		{
			name:                         "Secret not provisioned by cloud-credential-operator, bad conditions",
			manifest:                     makeFakeManifest(operandName, credentialRequestNamespace, operandNamespace),
			inputSecretProvisioned:       false,
			expectedAvailableCondition:   &conditionFalse,
			expectedProgressingCondition: &conditionTrue,
			expectedFailingStatus:        false,
		},
		{
			name:                  "Bad CredentialRequest manifest, controller degraded",
			manifest:              makeFakeManifest("wrong", credentialRequestNamespace, operandNamespace), // Wrong name will cause an error on Create()
			expectedFailingStatus: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize
			dynamicClient := &fakeDynamicClient{}
			cr := resourceread.ReadCredentialRequestsOrDie(tc.manifest)
			resourceapply.AddCredentialsRequestHash(cr)
			unstructured.SetNestedField(cr.Object, tc.inputSecretProvisioned, "status", "provisioned")
			dynamicClient.credentialRequest = cr

			operatorClient := v1helpers.NewFakeOperatorClient(&opv1.OperatorSpec{}, &opv1.OperatorStatus{}, nil)
			recorder := events.NewInMemoryRecorder("test")
			controller := NewCredentialsRequestController(
				controllerName,
				operandNamespace,
				tc.manifest,
				dynamicClient,
				operatorClient,
				recorder,
			)

			// Act
			err := controller.Sync(context.TODO(), factory.NewSyncContext("test", recorder))

			// Assert
			_, status, _, _ := operatorClient.GetOperatorState()

			if tc.expectedFailingStatus && err == nil {
				t.Fatalf("expected failed sync")
			}

			if !tc.expectedFailingStatus && err != nil {
				t.Fatalf("unexpected failed sync: %v", err)
			}

			if tc.expectedAvailableCondition != nil {
				if !isConditionSet(availableCondition, *tc.expectedAvailableCondition, status.Conditions) {
					t.Fatalf("expected %s=%s, found conditions %+v", availableCondition, *tc.expectedAvailableCondition, status.Conditions)
				}
			}

			if tc.expectedProgressingCondition != nil {
				if !isConditionSet(progressingCondition, *tc.expectedProgressingCondition, status.Conditions) {
					t.Fatalf("expected %s=%s, found conditions %+v", progressingCondition, *tc.expectedProgressingCondition, status.Conditions)
				}
			}
		})
	}
}

func isConditionSet(condition string, status opv1.ConditionStatus, conditions []opv1.OperatorCondition) bool {
	for i := range conditions {
		if condition == conditions[i].Type {
			if conditions[i].Status == status {
				return true
			}
		}
	}
	return false
}

func makeFakeManifest(operandName, crNamespace, operandNamespace string) []byte {
	value := `apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: %s
  namespace: %s
spec:
  secretRef:
    name: random-secret-name
    namespace: %s
`
	return []byte(
		fmt.Sprintf(
			value,
			operandName,
			crNamespace,
			operandNamespace,
		))
}

func checkCredentialsRequestSanity(obj *unstructured.Unstructured) error {
	if obj.GetKind() != credentialsRequestKind {
		return fmt.Errorf("expected kind %s, got %s", credentialsRequestKind, obj.GetKind())
	}
	if obj.GetNamespace() != credentialRequestNamespace {
		return fmt.Errorf("expected namespace %s, got %s", credentialRequestNamespace, obj.GetNamespace())
	}
	if obj.GetName() != operandName {
		return fmt.Errorf("expected name %s, got %s", operandName, obj.GetName())
	}

	manifest := makeFakeManifest(operandName, credentialRequestNamespace, operandNamespace)
	expectedObj := resourceread.ReadCredentialRequestsOrDie(manifest)
	expectedSpec := expectedObj.Object["spec"]
	actualSpec := obj.Object["spec"]
	if !reflect.DeepEqual(expectedSpec, actualSpec) {
		return fmt.Errorf("expected different spec")
	}
	return nil
}

// Fakes

type fakeDynamicClient struct {
	credentialRequest *unstructured.Unstructured
}

var (
	_ dynamic.Interface                      = &fakeDynamicClient{}
	_ dynamic.ResourceInterface              = &fakeDynamicClient{}
	_ dynamic.NamespaceableResourceInterface = &fakeDynamicClient{}

	credentialsGR schema.GroupResource = schema.GroupResource{
		Group:    resourceapply.CredentialsRequestGroup,
		Resource: resourceapply.CredentialsRequestResource,
	}
)

func (fake *fakeDynamicClient) Resource(resource schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return fake
}

func (fake *fakeDynamicClient) Namespace(string) dynamic.ResourceInterface {
	return fake
}

func (fake *fakeDynamicClient) Create(ctx context.Context, obj *unstructured.Unstructured, options metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	if err := checkCredentialsRequestSanity(obj); err != nil {
		return nil, err
	}
	if fake.credentialRequest != nil {
		return nil, apierrors.NewAlreadyExists(credentialsGR, obj.GetName())
	}
	fake.credentialRequest = obj.DeepCopy()
	fake.credentialRequest.SetGeneration(1)
	fake.credentialRequest.SetResourceVersion("1")
	return fake.credentialRequest, nil
}

func (fake *fakeDynamicClient) Update(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	if err := checkCredentialsRequestSanity(obj); err != nil {
		return nil, err
	}
	if fake.credentialRequest == nil {
		return nil, apierrors.NewNotFound(credentialsGR, obj.GetName())
	}
	fake.credentialRequest = obj.DeepCopy()
	fake.credentialRequest.SetGeneration(obj.GetGeneration() + 1)
	gen, _ := strconv.Atoi(obj.GetResourceVersion())
	fake.credentialRequest.SetResourceVersion(strconv.Itoa(gen + 1))
	return fake.credentialRequest, nil
}

func (fake *fakeDynamicClient) UpdateStatus(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return nil, errors.New("not implemented")
}

func (fake *fakeDynamicClient) Delete(ctx context.Context, name string, options metav1.DeleteOptions, subresources ...string) error {
	if fake.credentialRequest == nil {
		return apierrors.NewNotFound(credentialsGR, name)
	}
	fake.credentialRequest = nil
	return nil
}

func (fake *fakeDynamicClient) DeleteCollection(ctx context.Context, options metav1.DeleteOptions, listOptions metav1.ListOptions) error {
	return errors.New("not implemented")
}

func (fake *fakeDynamicClient) Get(ctx context.Context, name string, options metav1.GetOptions, subresources ...string) (*unstructured.Unstructured, error) {
	if fake.credentialRequest == nil {
		return nil, apierrors.NewNotFound(credentialsGR, name)
	}
	if fake.credentialRequest.GetName() != name {
		return nil, apierrors.NewNotFound(credentialsGR, name)
	}
	return fake.credentialRequest, nil
}

func (fake *fakeDynamicClient) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return nil, errors.New("not implemented")
}

func (fake *fakeDynamicClient) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return nil, errors.New("not implemented")
}

func (fake *fakeDynamicClient) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, options metav1.PatchOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, errors.New("not implemented")
}
