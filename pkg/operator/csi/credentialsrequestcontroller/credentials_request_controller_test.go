package credentialsrequestcontroller

import (
	"context"
	"errors"
	"fmt"
	clocktesting "k8s.io/utils/clock/testing"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"

	opv1 "github.com/openshift/api/operator/v1"

	fakeoperatorv1client "github.com/openshift/client-go/operator/clientset/versioned/fake"
	operatorinformer "github.com/openshift/client-go/operator/informers/externalversions"
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
	cloudCredential              *opv1.CloudCredential
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
			cloudCredential: &opv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterCloudCredentialName,
				},
				Spec: opv1.CloudCredentialSpec{
					CredentialsMode: opv1.CloudCredentialsModeDefault,
				},
			},
			expectedFailingStatus: false,
		},
		{
			name:                   "Secret not provisioned by cloud-credential-operator, bad conditions",
			manifest:               makeFakeManifest(operandName, credentialRequestNamespace, operandNamespace),
			inputSecretProvisioned: false,
			cloudCredential: &opv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterCloudCredentialName,
				},
				Spec: opv1.CloudCredentialSpec{
					CredentialsMode: opv1.CloudCredentialsModeDefault,
				},
			},
			expectedAvailableCondition:   &conditionFalse,
			expectedProgressingCondition: &conditionTrue,
			expectedFailingStatus:        false,
		},
		{
			name: "Bad CredentialRequest manifest, controller degraded",
			cloudCredential: &opv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterCloudCredentialName,
				},
				Spec: opv1.CloudCredentialSpec{
					CredentialsMode: opv1.CloudCredentialsModeDefault,
				},
			},
			manifest:              makeFakeManifest("wrong", credentialRequestNamespace, operandNamespace), // Wrong name will cause an error on Create()
			expectedFailingStatus: true,
		},
		{
			name: "Bad CredentialRequest manifest, in manual mode",
			cloudCredential: &opv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterCloudCredentialName,
				},
				Spec: opv1.CloudCredentialSpec{
					CredentialsMode: opv1.CloudCredentialsModeManual,
				},
			},
			manifest:              makeFakeManifest("wrong", credentialRequestNamespace, operandNamespace), // Wrong name will cause an error on Create()
			expectedFailingStatus: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize
			dynamicClient := &fakeDynamicClient{}
			typedVersionedOperatorClient := fakeoperatorv1client.NewSimpleClientset(tc.cloudCredential)
			cloudCredentialinformer := operatorinformer.NewSharedInformerFactory(typedVersionedOperatorClient, 1*time.Minute)
			// add object to the indexer
			cloudCredentialinformer.Operator().V1().CloudCredentials().Informer().GetIndexer().Add(tc.cloudCredential)

			cr := resourceread.ReadCredentialRequestsOrDie(tc.manifest)
			resourceapply.AddCredentialsRequestHash(cr)
			unstructured.SetNestedField(cr.Object, tc.inputSecretProvisioned, "status", "provisioned")
			dynamicClient.credentialRequest = cr

			operatorClient := v1helpers.NewFakeOperatorClient(&opv1.OperatorSpec{
				ManagementState: opv1.Managed,
			}, &opv1.OperatorStatus{}, nil)
			recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))
			controller := NewCredentialsRequestController(
				controllerName,
				operandNamespace,
				tc.manifest,
				dynamicClient,
				operatorClient,
				cloudCredentialinformer,
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

func (fake *fakeDynamicClient) Apply(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, errors.New("not implemented")
}

func (fake *fakeDynamicClient) ApplyStatus(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	return nil, errors.New("not implemented")
}

func TestShouldSync(t *testing.T) {
	tests := []struct {
		name               string
		cloudCredential    *opv1.CloudCredential
		envVars            map[string]string
		expectedShouldSync bool
		expectedError      bool
	}{
		{
			name: "Default mode",
			cloudCredential: &opv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterCloudCredentialName,
				},
				Spec: opv1.CloudCredentialSpec{
					CredentialsMode: opv1.CloudCredentialsModeDefault,
				},
			},
			expectedShouldSync: true,
			expectedError:      false,
		},
		{
			name: "Manual mode without short-term credentials",
			cloudCredential: &opv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterCloudCredentialName,
				},
				Spec: opv1.CloudCredentialSpec{
					CredentialsMode: opv1.CloudCredentialsModeManual,
				},
			},
			expectedShouldSync: false,
			expectedError:      false,
		},
		{
			name: "Manual mode with AWS STS enabled",
			cloudCredential: &opv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterCloudCredentialName,
				},
				Spec: opv1.CloudCredentialSpec{
					CredentialsMode: opv1.CloudCredentialsModeManual,
				},
			},
			envVars: map[string]string{
				"ROLEARN": "arn:aws:iam::123456789012:role/test-role",
			},
			expectedShouldSync: true,
			expectedError:      false,
		},
		{
			name: "Manual mode with GCP WIF enabled",
			cloudCredential: &opv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterCloudCredentialName,
				},
				Spec: opv1.CloudCredentialSpec{
					CredentialsMode: opv1.CloudCredentialsModeManual,
				},
			},
			envVars: map[string]string{
				"POOL_ID":               "test-pool",
				"PROVIDER_ID":           "test-provider",
				"SERVICE_ACCOUNT_EMAIL": "test@example.com",
				"PROJECT_NUMBER":        "123456789",
			},
			expectedShouldSync: true,
			expectedError:      false,
		},
		{
			name: "Manual mode with partial GCP WIF configuration",
			cloudCredential: &opv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterCloudCredentialName,
				},
				Spec: opv1.CloudCredentialSpec{
					CredentialsMode: opv1.CloudCredentialsModeManual,
				},
			},
			envVars: map[string]string{
				"POOL_ID":               "test-pool",
				"PROVIDER_ID":           "test-provider",
				"SERVICE_ACCOUNT_EMAIL": "test@example.com",
			},
			expectedShouldSync: false,
			expectedError:      false,
		},
		{
			name:               "Error getting cloud credential",
			cloudCredential:    nil,
			expectedShouldSync: false,
			expectedError:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			typedVersionedOperatorClient := fakeoperatorv1client.NewSimpleClientset()
			cloudCredentialInformer := operatorinformer.NewSharedInformerFactory(typedVersionedOperatorClient, 1*time.Minute)

			if tc.cloudCredential != nil {
				err := cloudCredentialInformer.Operator().V1().CloudCredentials().Informer().GetStore().Add(tc.cloudCredential)
				if err != nil {
					t.Fatalf("Failed to add cloud credential to store: %v", err)
				}
			}

			// Set environment variables
			for k, v := range tc.envVars {
				os.Setenv(k, v)
			}
			defer func() {
				for k := range tc.envVars {
					os.Unsetenv(k)
				}
			}()

			// Act
			shouldSync, err := shouldSync(cloudCredentialInformer.Operator().V1().CloudCredentials().Lister())

			// Assert
			if tc.expectedError && err == nil {
				t.Error("Expected an error, but got none")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if shouldSync != tc.expectedShouldSync {
				t.Errorf("Expected shouldSync to be %v, but got %v", tc.expectedShouldSync, shouldSync)
			}
		})
	}
}
