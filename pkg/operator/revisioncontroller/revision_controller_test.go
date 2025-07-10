package revisioncontroller

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/klog/v2"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
)

func filterCreateActions(actions []clienttesting.Action) []runtime.Object {
	var createdObjects []runtime.Object
	for _, a := range actions {
		createAction, isCreate := a.(clienttesting.CreateAction)
		if !isCreate {
			continue
		}
		// Filter out Update actions as both clienttesting.CreateAction
		// and clienttesting.UpdateAction implement the same interface
		if reflect.TypeOf(a) == reflect.TypeOf(clienttesting.UpdateActionImpl{}) {
			continue
		}
		_, isEvent := createAction.GetObject().(*v1.Event)
		if isEvent {
			continue
		}
		createdObjects = append(createdObjects, createAction.GetObject())
	}
	return createdObjects
}

func filterUpdateActions(actions []clienttesting.Action) []runtime.Object {
	var updatedObjects []runtime.Object
	for _, a := range actions {
		updateAction, isUpdate := a.(clienttesting.UpdateAction)
		if !isUpdate {
			continue
		}
		_, isEvent := updateAction.GetObject().(*v1.Event)
		if isEvent {
			continue
		}
		updatedObjects = append(updatedObjects, updateAction.GetObject())
	}
	return updatedObjects
}

const targetNamespace = "copy-resources"

func TestRevisionController(t *testing.T) {
	tests := []struct {
		testName                string
		targetNamespace         string
		testSecrets             []RevisionResource
		testConfigs             []RevisionResource
		startingObjects         []runtime.Object
		staticPodOperatorClient v1helpers.StaticPodOperatorClient
		validateActions         func(t *testing.T, actions []clienttesting.Action, kclient *fake.Clientset)
		validateStatus          func(t *testing.T, status *operatorv1.StaticPodOperatorStatus)
		expectSyncError         string
	}{
		{
			testName:        "update InProgress to Abandoned revisions when interrupted",
			targetNamespace: targetNamespace,
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					LatestAvailableRevision: 1,
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 1,
							TargetRevision:  2,
						},
					},
				},
				nil,
				nil,
			),
			testConfigs: []RevisionResource{{Name: "test-config"}},
			testSecrets: []RevisionResource{{Name: "test-secret"}},
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status", Namespace: targetNamespace}},
				&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "revision-status-1", Namespace: targetNamespace},
					Data:       map[string]string{"revision": "1"},
				},
			},
			validateActions: func(t *testing.T, actions []clienttesting.Action, kclient *fake.Clientset) {
				updatedObjects := filterUpdateActions(actions)
				if len(updatedObjects) != 4 {
					t.Errorf("expected 4 updated objects, but got %v", len(updatedObjects))
				}
				_, err := kclient.CoreV1().ConfigMaps(targetNamespace).Get(context.TODO(), "revision-status-2", metav1.GetOptions{})
				if err != nil {
					t.Errorf("error getting revision-status-2 map")
					return
				}
			},
		},
		{
			testName:        "set-latest-revision-by-configmap",
			targetNamespace: targetNamespace,
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					LatestAvailableRevision: 0,
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 0,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			testConfigs: []RevisionResource{{Name: "test-config"}},
			testSecrets: []RevisionResource{{Name: "test-secret"}},
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status", Namespace: targetNamespace}},
				&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name: "revision-status-1", Namespace: targetNamespace,
						Annotations: map[string]string{"operator.openshift.io/revision-ready": "true"},
					},
					Data: map[string]string{"revision": "1"},
				},
				&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name: "revision-status-2", Namespace: targetNamespace,
						Annotations: map[string]string{"operator.openshift.io/revision-ready": "true"},
					},
					Data: map[string]string{"revision": "2"},
				},
			},
			validateStatus: func(t *testing.T, status *operatorv1.StaticPodOperatorStatus) {
				if status.LatestAvailableRevision != 2 {
					t.Errorf("expected status LatestAvailableRevision to be 2, got %v", status.LatestAvailableRevision)
				}
			},
		},
		{
			testName:        "operator-unmanaged",
			targetNamespace: targetNamespace,
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Unmanaged,
					},
				},
				&operatorv1.StaticPodOperatorStatus{},
				nil,
				nil,
			),
			validateActions: func(t *testing.T, actions []clienttesting.Action, kclient *fake.Clientset) {
				createdObjects := filterCreateActions(actions)
				if createdObjectCount := len(createdObjects); createdObjectCount != 0 {
					t.Errorf("expected no objects to be created, got %d", createdObjectCount)
				}
			},
		},
		{
			testName:        "missing-source-resources",
			targetNamespace: targetNamespace,
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					LatestAvailableRevision: 1,
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 0,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			testConfigs:     []RevisionResource{{Name: "test-config"}},
			testSecrets:     []RevisionResource{{Name: "test-secret"}},
			expectSyncError: "synthetic requeue request",
			validateStatus: func(t *testing.T, status *operatorv1.StaticPodOperatorStatus) {
				if status.Conditions[0].Type != "RevisionControllerDegraded" {
					t.Errorf("expected status condition to be 'RevisionControllerFailing', got %v", status.Conditions[0].Type)
				}
				if status.Conditions[0].Reason != "ContentCreationError" {
					t.Errorf("expected status condition reason to be 'ContentCreationError', got %v", status.Conditions[0].Reason)
				}
				if !strings.Contains(status.Conditions[0].Message, `configmaps "test-config" not found`) {
					t.Errorf("expected status to be 'configmaps test-config not found', got: %s", status.Conditions[0].Message)
				}
			},
			validateActions: func(t *testing.T, actions []clienttesting.Action, kclient *fake.Clientset) {
				createdObjects := filterCreateActions(actions)
				if createdObjectCount := len(createdObjects); createdObjectCount != 0 {
					t.Errorf("expected no objects to be created, got %d", createdObjectCount)
				}
			},
		},
		{
			testName:        "copy-resources",
			targetNamespace: targetNamespace,
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					LatestAvailableRevision: 0,
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 0,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status", Namespace: targetNamespace}},
			},
			testConfigs: []RevisionResource{{Name: "test-config"}},
			testSecrets: []RevisionResource{{Name: "test-secret"}},
			validateActions: func(t *testing.T, actions []clienttesting.Action, kclient *fake.Clientset) {
				createdObjects := filterCreateActions(actions)
				if createdObjectCount := len(createdObjects); createdObjectCount != 3 {
					t.Errorf("expected 3 objects to be created, got %d: %+v", createdObjectCount, createdObjects)
					return
				}
				revisionStatus, hasStatus := createdObjects[0].(*v1.ConfigMap)
				if !hasStatus {
					t.Errorf("expected config to be created")
					return
				}
				if revisionStatus.Name != "revision-status-1" {
					t.Errorf("expected config to have name 'revision-status-1', got %q", revisionStatus.Name)
				}
				config, hasConfig := createdObjects[1].(*v1.ConfigMap)
				if !hasConfig {
					t.Errorf("expected config to be created")
					return
				}
				if config.Name != "test-config-1" {
					t.Errorf("expected config to have name 'test-config-1', got %q", config.Name)
				}
				if len(config.OwnerReferences) != 1 {
					t.Errorf("expected config to have ownerreferences set, got %+v", config.OwnerReferences)
				}
				secret, hasSecret := createdObjects[2].(*v1.Secret)
				if !hasSecret {
					t.Errorf("expected secret to be created")
					return
				}
				if secret.Name != "test-secret-1" {
					t.Errorf("expected secret to have name 'test-secret-1', got %q", secret.Name)
				}
				if len(secret.OwnerReferences) != 1 {
					t.Errorf("expected secret to have ownerreferences set, got %+v", secret.OwnerReferences)
				}
			},
		},
		{
			testName:        "copy-resources-opt",
			targetNamespace: targetNamespace,
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					LatestAvailableRevision: 0,
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 0,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret-opt", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config-opt", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status", Namespace: targetNamespace}},
			},
			testConfigs: []RevisionResource{{Name: "test-config"}, {Name: "test-config-opt", Optional: true}},
			testSecrets: []RevisionResource{{Name: "test-secret"}, {Name: "test-secret-opt", Optional: true}},
			validateActions: func(t *testing.T, actions []clienttesting.Action, kclient *fake.Clientset) {
				createdObjects := filterCreateActions(actions)
				if createdObjectCount := len(createdObjects); createdObjectCount != 5 {
					t.Errorf("expected 5 objects to be created, got %d: %+v", createdObjectCount, createdObjects)
					return
				}
				revisionStatus, hasStatus := createdObjects[0].(*v1.ConfigMap)
				if !hasStatus {
					t.Errorf("expected config to be created")
					return
				}
				if revisionStatus.Name != "revision-status-1" {
					t.Errorf("expected config to have name 'revision-status-1', got %q", revisionStatus.Name)
				}
				config, hasConfig := createdObjects[1].(*v1.ConfigMap)
				if !hasConfig {
					t.Errorf("expected config to be created")
					return
				}
				if config.Name != "test-config-1" {
					t.Errorf("expected config to have name 'test-config-1', got %q", config.Name)
				}
				config, hasConfig = createdObjects[2].(*v1.ConfigMap)
				if !hasConfig {
					t.Errorf("expected config to be created")
					return
				}
				if config.Name != "test-config-opt-1" {
					t.Errorf("expected config to have name 'test-config-opt-1', got %q", config.Name)
				}
				secret, hasSecret := createdObjects[3].(*v1.Secret)
				if !hasSecret {
					t.Errorf("expected secret to be created")
					return
				}
				if secret.Name != "test-secret-1" {
					t.Errorf("expected secret to have name 'test-secret-1', got %q", secret.Name)
				}
				secret, hasSecret = createdObjects[4].(*v1.Secret)
				if !hasSecret {
					t.Errorf("expected secret to be created")
					return
				}
				if secret.Name != "test-secret-opt-1" {
					t.Errorf("expected secret to have name 'test-secret-opt-1', got %q", secret.Name)
				}
			},
		},
		{
			testName:        "copy-resources-opt-missing",
			targetNamespace: targetNamespace,
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					LatestAvailableRevision: 0,
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 0,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status", Namespace: targetNamespace}},
			},
			testConfigs: []RevisionResource{{Name: "test-config"}, {Name: "test-config-opt", Optional: true}},
			testSecrets: []RevisionResource{{Name: "test-secret"}, {Name: "test-secret-opt", Optional: true}},
			validateActions: func(t *testing.T, actions []clienttesting.Action, kclient *fake.Clientset) {
				createdObjects := filterCreateActions(actions)
				if createdObjectCount := len(createdObjects); createdObjectCount != 3 {
					t.Errorf("expected 3 objects to be created, got %d: %+v", createdObjectCount, createdObjects)
					return
				}
				revisionStatus, hasStatus := createdObjects[0].(*v1.ConfigMap)
				if !hasStatus {
					t.Errorf("expected config to be created")
					return
				}
				if revisionStatus.Name != "revision-status-1" {
					t.Errorf("expected config to have name 'revision-status-1', got %q", revisionStatus.Name)
				}
				config, hasConfig := createdObjects[1].(*v1.ConfigMap)
				if !hasConfig {
					t.Errorf("expected config to be created")
					return
				}
				if config.Name != "test-config-1" {
					t.Errorf("expected config to have name 'test-config-1', got %q", config.Name)
				}
				secret, hasSecret := createdObjects[2].(*v1.Secret)
				if !hasSecret {
					t.Errorf("expected secret to be created")
					return
				}
				if secret.Name != "test-secret-1" {
					t.Errorf("expected secret to have name 'test-secret-1', got %q", secret.Name)
				}
			},
		},
		{
			testName:        "latest-revision-current",
			targetNamespace: targetNamespace,
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					LatestAvailableRevision: 1,
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 0,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret-1", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config-1", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status-1", Namespace: targetNamespace}},
			},
			testConfigs: []RevisionResource{{Name: "test-config"}},
			testSecrets: []RevisionResource{{Name: "test-secret"}},
			validateActions: func(t *testing.T, actions []clienttesting.Action, kclient *fake.Clientset) {
				createdObjects := filterCreateActions(actions)
				if createdObjectCount := len(createdObjects); createdObjectCount != 0 {
					t.Errorf("expected no objects to be created, got %d", createdObjectCount)
				}
			},
		},
		{
			testName:        "latest-revision-current-optionals-missing",
			targetNamespace: targetNamespace,
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					LatestAvailableRevision: 1,
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 0,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret-1", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config-1", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status-1", Namespace: targetNamespace}},
			},
			testConfigs: []RevisionResource{{Name: "test-config"}, {Name: "test-config-opt", Optional: true}},
			testSecrets: []RevisionResource{{Name: "test-secret"}, {Name: "test-secret-opt", Optional: true}},
			validateActions: func(t *testing.T, actions []clienttesting.Action, kclient *fake.Clientset) {
				createdObjects := filterCreateActions(actions)
				if createdObjectCount := len(createdObjects); createdObjectCount != 0 {
					t.Errorf("expected no objects to be created, got %d", createdObjectCount)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset(tc.startingObjects...)
			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &v1.ObjectReference{})

			c := NewRevisionController(
				tc.targetNamespace,
				tc.testConfigs,
				tc.testSecrets,
				informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace(tc.targetNamespace)),
				StaticPodLatestRevisionClient{StaticPodOperatorClient: tc.staticPodOperatorClient},
				kubeClient.CoreV1(),
				kubeClient.CoreV1(),
				eventRecorder,
			)
			syncErr := c.Sync(context.TODO(), factory.NewSyncContext("RevisionController", eventRecorder))
			if tc.validateStatus != nil {
				_, status, _, _ := tc.staticPodOperatorClient.GetStaticPodOperatorState()
				tc.validateStatus(t, status)
			}
			if tc.validateActions != nil {
				tc.validateActions(t, kubeClient.Actions(), kubeClient)
			}
			if syncErr != nil {
				if !strings.Contains(syncErr.Error(), tc.expectSyncError) {
					t.Errorf("expected %q string in error %q", tc.expectSyncError, syncErr.Error())
				}
				return
			}
			if syncErr == nil && len(tc.expectSyncError) != 0 {
				t.Errorf("expected %v error, got none", tc.expectSyncError)
				return
			}
		})
	}
}

type fakeStaticPodLatestRevisionClient struct {
	v1helpers.StaticPodOperatorClient
	client                                 *StaticPodLatestRevisionClient
	updateLatestRevisionOperatorStatusErrs bool
}

var _ LatestRevisionClient = &fakeStaticPodLatestRevisionClient{}

func (c fakeStaticPodLatestRevisionClient) GetLatestRevisionState() (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, int32, string, error) {
	return c.client.GetLatestRevisionState()
}

func (c fakeStaticPodLatestRevisionClient) UpdateLatestRevisionOperatorStatus(ctx context.Context, latestAvailableRevision int32, updateFuncs ...v1helpers.UpdateStatusFunc) (*operatorv1.OperatorStatus, bool, error) {
	if c.updateLatestRevisionOperatorStatusErrs {
		return nil, false, fmt.Errorf("Operation cannot be fulfilled on kubeapiservers.operator.openshift.io \"cluster\": the object has been modified; please apply your changes to the latest version and try again")
	}
	return c.client.UpdateLatestRevisionOperatorStatus(ctx, latestAvailableRevision, updateFuncs...)
}

func TestRevisionControllerRevisionCreatedFailedStatusUpdate(t *testing.T) {
	startingObjects := []runtime.Object{
		&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
		&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret-2", Namespace: targetNamespace}},
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}, Data: map[string]string{"key": "value", "key2": "value"}},
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config-2", Namespace: targetNamespace}, Data: map[string]string{"key": "value"}},
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status-2", Namespace: targetNamespace, Annotations: map[string]string{"operator.openshift.io/revision-ready": "false"}}},
	}

	testConfigs := []RevisionResource{{Name: "test-config"}, {Name: "test-config-opt", Optional: true}}
	testSecrets := []RevisionResource{{Name: "test-secret"}, {Name: "test-secret-opt", Optional: true}}

	staticPodOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{
			OperatorSpec: operatorv1.OperatorSpec{
				ManagementState: operatorv1.Managed,
			},
		},
		&operatorv1.StaticPodOperatorStatus{
			LatestAvailableRevision: 2,
			NodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName:        "test-node-1",
					CurrentRevision: 0,
					TargetRevision:  0,
				},
			},
		},
		nil,
		nil,
	)

	fakeStaticPodOperatosClient := &fakeStaticPodLatestRevisionClient{client: &StaticPodLatestRevisionClient{StaticPodOperatorClient: staticPodOperatorClient}, StaticPodOperatorClient: staticPodOperatorClient}

	kubeClient := fake.NewSimpleClientset(startingObjects...)
	eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &v1.ObjectReference{})

	c := NewRevisionController(
		targetNamespace,
		testConfigs,
		testSecrets,
		informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace(targetNamespace)),
		fakeStaticPodOperatosClient,
		kubeClient.CoreV1(),
		kubeClient.CoreV1(),
		eventRecorder,
	)

	klog.Infof("Running NewRevisionController.Sync with UpdateLatestRevisionOperatorStatus returning an error")
	// make the first UpdateLatestRevisionOperatorStatus call fail
	fakeStaticPodOperatosClient.updateLatestRevisionOperatorStatusErrs = true
	syncErr := c.Sync(context.TODO(), factory.NewSyncContext("RevisionController", eventRecorder))
	klog.Infof("Validating NewRevisionController.Sync returned an error: %v", syncErr)
	if syncErr == nil {
		t.Errorf("expected error after running NewRevisionController.Sync, got nil")
		return
	}
	_, status, _, statusErr := staticPodOperatorClient.GetStaticPodOperatorState()
	if statusErr != nil {
		t.Errorf("unexpected status err: %v", statusErr)
		return
	}
	klog.Infof("Validating status.LatestAvailableRevision (%v) has not changed", status.LatestAvailableRevision)
	if status.LatestAvailableRevision != 2 {
		t.Errorf("unexpected status.LatestAvailableRevision: %v, expected 2", status.LatestAvailableRevision)
		return
	}

	klog.Infof("Running NewRevisionController.Sync with UpdateLatestRevisionOperatorStatus succeeding")
	// make the second UpdateLatestRevisionOperatorStatus call to succeed
	fakeStaticPodOperatosClient.updateLatestRevisionOperatorStatusErrs = false
	syncErr = c.Sync(context.TODO(), factory.NewSyncContext("RevisionController", eventRecorder))
	if syncErr != nil && syncErr != factory.SyntheticRequeueError {
		t.Errorf("unexpected error after running NewRevisionController.Sync: %v", syncErr)
		return
	}
	_, status, _, statusErr = staticPodOperatorClient.GetStaticPodOperatorState()
	if statusErr != nil {
		t.Errorf("unexpected status err: %v", statusErr)
		return
	}
	klog.Infof("Validating status.LatestAvailableRevision (%v) changed", status.LatestAvailableRevision)
	if status.LatestAvailableRevision != 3 {
		t.Errorf("unexpected status.LatestAvailableRevision: %v, expected 3", status.LatestAvailableRevision)
		return
	}
}
