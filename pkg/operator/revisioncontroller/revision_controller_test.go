package revisioncontroller

import (
	"context"
	"fmt"
	clocktesting "k8s.io/utils/clock/testing"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/stretchr/testify/require"

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
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
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
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 0,
					},
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
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
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
			expectSyncError: `configmaps "test-config" not found`,
			validateStatus: func(t *testing.T, status *operatorv1.StaticPodOperatorStatus) {
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
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 0,
					},
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
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 0,
					},
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
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 0,
					},
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
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
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
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
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
			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &v1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))

			c := NewRevisionController(
				"testing",
				tc.targetNamespace,
				tc.testConfigs,
				tc.testSecrets,
				informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace(tc.targetNamespace)),
				tc.staticPodOperatorClient,
				kubeClient.CoreV1(),
				kubeClient.CoreV1(),
				eventRecorder,
				nil,
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

	type errorContainer struct {
		err error
	}
	testErr := &errorContainer{}

	errFn := func(rv string, status *operatorv1.StaticPodOperatorStatus) error {
		return testErr.err
	}
	staticPodOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{
			OperatorSpec: operatorv1.OperatorSpec{
				ManagementState: operatorv1.Managed,
			},
		},
		&operatorv1.StaticPodOperatorStatus{
			OperatorStatus: operatorv1.OperatorStatus{
				LatestAvailableRevision: 2,
			},
			NodeStatuses: []operatorv1.NodeStatus{
				{
					NodeName:        "test-node-1",
					CurrentRevision: 0,
					TargetRevision:  0,
				},
			},
		},
		errFn,
		nil,
	)

	kubeClient := fake.NewSimpleClientset(startingObjects...)
	eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &v1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))

	c := NewRevisionController(
		"testing",
		targetNamespace,
		testConfigs,
		testSecrets,
		informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace(targetNamespace)),
		staticPodOperatorClient,
		kubeClient.CoreV1(),
		kubeClient.CoreV1(),
		eventRecorder,
		nil,
	)

	klog.Infof("Running NewRevisionController.Sync with UpdateLatestRevisionOperatorStatus returning an error")
	// make the first UpdateLatestRevisionOperatorStatus call fail
	testErr.err = fmt.Errorf("applyStatusFailure")
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
	testErr.err = nil
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

func TestSyncWithRevisionPrecondition(t *testing.T) {
	tests := []struct {
		testName                          string
		targetNamespace                   string
		testConfigs                       []RevisionResource
		testSecrets                       []RevisionResource
		startingObjects                   []runtime.Object
		staticPodOperatorClient           v1helpers.StaticPodOperatorClient
		revisionPrecondition              PreconditionFunc
		expSyncErr                        error
		expUpdatedLatestAvailableRevision int32
	}{
		{
			// when revision precondition is nil, the default implementation is considered. In this case no error is expected to be
			// returned by sync and LatestAvailableRevision should be updated
			testName:        "revision precondition is not supplied",
			targetNamespace: targetNamespace,
			testConfigs:     []RevisionResource{{Name: "test-config"}},
			testSecrets:     []RevisionResource{{Name: "test-secret"}},
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status", Namespace: targetNamespace}},
				&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "revision-status-1", Namespace: targetNamespace},
					Data:       map[string]string{"revision": "1"},
				},
			},
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 1,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			revisionPrecondition:              nil,
			expSyncErr:                        nil,
			expUpdatedLatestAvailableRevision: 2,
		},
		{
			// when revision precondition is false, no error should be returned by sync but LatestAvailableRevision should not be updated
			testName:        "revision precondtion is false",
			targetNamespace: targetNamespace,
			testConfigs:     []RevisionResource{{Name: "test-config"}},
			testSecrets:     []RevisionResource{{Name: "test-secret"}},
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status", Namespace: targetNamespace}},
				&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "revision-status-1", Namespace: targetNamespace},
					Data:       map[string]string{"revision": "1"},
				},
			},
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 1,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			revisionPrecondition: func(ctx context.Context) (bool, error) {
				return false, nil
			},
			expSyncErr:                        nil,
			expUpdatedLatestAvailableRevision: 1,
		},
		{
			// when revision precondition check returns error, the same error should be returned by sync and LatestAvailableRevision should not be updated
			testName:        "revision precondition is true but precondition check returns error",
			targetNamespace: targetNamespace,
			testConfigs:     []RevisionResource{{Name: "test-config"}},
			testSecrets:     []RevisionResource{{Name: "test-secret"}},
			startingObjects: []runtime.Object{
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: targetNamespace}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision-status", Namespace: targetNamespace}},
				&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "revision-status-1", Namespace: targetNamespace},
					Data:       map[string]string{"revision": "1"},
				},
			},
			staticPodOperatorClient: v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						LatestAvailableRevision: 1,
					},
					NodeStatuses: []operatorv1.NodeStatus{
						{
							NodeName:        "test-node-1",
							CurrentRevision: 1,
							TargetRevision:  0,
						},
					},
				},
				nil,
				nil,
			),
			revisionPrecondition: func(ctx context.Context) (bool, error) {
				return true, fmt.Errorf("Error")
			},
			expSyncErr:                        fmt.Errorf("Error"),
			expUpdatedLatestAvailableRevision: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset(tc.startingObjects...)
			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &v1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))

			c := NewRevisionController(
				"testing",
				tc.targetNamespace,
				tc.testConfigs,
				tc.testSecrets,
				informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace(targetNamespace)),
				tc.staticPodOperatorClient,
				kubeClient.CoreV1(),
				kubeClient.CoreV1(),
				eventRecorder,
				tc.revisionPrecondition,
			)
			syncErr := c.Sync(context.TODO(), factory.NewSyncContext("RevisionController", eventRecorder))
			require.Equal(t, syncErr, tc.expSyncErr)

			_, status, _, _ := tc.staticPodOperatorClient.GetStaticPodOperatorState()
			require.Equal(t, tc.expUpdatedLatestAvailableRevision, status.LatestAvailableRevision)

		})
	}
}
