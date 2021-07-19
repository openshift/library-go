package staticresourcecontroller

import (
	"context"
	"testing"

	"github.com/davecgh/go-spew/spew"

	"github.com/stretchr/testify/assert"

	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakecore "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/restmapper"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/diff"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/client/openshiftrestmapper"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestRelatedObjects(t *testing.T) {
	sa := `apiVersion: v1
kind: ServiceAccount
metadata:
  name: aws-ebs-csi-driver-operator
  namespace: openshift-cluster-csi-drivers
`

	secret := `apiVersion: v1
kind: Secret
metadata:
  name: aws-ebs-csi-driver-operator
  namespace: openshift-cluster-csi-drivers
`
	expected := []configv1.ObjectReference{
		{
			Group:     "",
			Resource:  "serviceaccounts",
			Namespace: "openshift-cluster-csi-drivers",
			Name:      "aws-ebs-csi-driver-operator",
		},
	}
	expander := restmapper.SimpleCategoryExpander{
		Expansions: map[string][]schema.GroupResource{
			"all": {
				{Group: "", Resource: "secrets"},
			},
		},
	}
	restMapper := openshiftrestmapper.NewOpenShiftHardcodedRESTMapper(nil)
	operatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{},
		&operatorv1.OperatorStatus{},
		nil,
	)
	assets := map[string]string{"secret": secret, "sa": sa}
	readBytesFromString := func(filename string) ([]byte, error) {
		return []byte(assets[filename]), nil
	}

	src := NewStaticResourceController("", readBytesFromString, []string{"secret", "sa"}, nil, operatorClient, events.NewInMemoryRecorder(""))
	src = src.AddRESTMapper(restMapper).AddCategoryExpander(expander)
	res, _ := src.RelatedObjects()
	assert.ElementsMatch(t, expected, res)
}

func makePDBManifest() []byte {
	return []byte(`
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: foo
  namespace: abc
`)
}

// fakeOperatorInstance is a fake Operator instance that  fullfils the OperatorClient interface.
type fakeOperatorInstance struct {
	metav1.ObjectMeta
	Spec   opv1.OperatorSpec
	Status opv1.OperatorStatus
}

func makeFakeOperatorInstance() *fakeOperatorInstance {
	instance := &fakeOperatorInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cluster",
			Generation: 0,
		},
		Spec: opv1.OperatorSpec{
			ManagementState: opv1.Managed,
		},
		Status: opv1.OperatorStatus{},
	}
	return instance
}

func TestStaticResourceController_WithConditionalResource_Sync(t *testing.T) {
	testCases := []struct {
		name                  string
		files                 []string
		conditionalFiles      []string
		createConditionalFunc resourceapply.ConditionalFunction
		deleteConditionalFunc resourceapply.ConditionalFunction
		existing              []runtime.Object
		expectError           bool
		verifyActions         func(actions []clienttesting.Action, t *testing.T)
	}{
		{
			name:  "static resource with no conditionals, create resource normally",
			files: []string{"pdb.yaml"},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
				expected := &policyv1.PodDisruptionBudget{
					TypeMeta: metav1.TypeMeta{
						Kind:       "PodDisruptionBudget",
						APIVersion: "policy/v1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "abc"},
				}
				actual := actions[1].(clienttesting.CreateAction).GetObject().(*policyv1.PodDisruptionBudget)
				if !equality.Semantic.DeepEqual(expected, actual) {
					t.Error(diff.ObjectDiff(expected, actual))
				}
			},
		},
		{
			name:                  "static resource with conditionalResource, delete will be honored",
			conditionalFiles:      []string{"pdb.yaml"},
			deleteConditionalFunc: func() bool { return true },
			createConditionalFunc: nil,
			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "abc",
					},
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("delete", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name:                  "static resource with delete conditional and create conditional, delete will be honored",
			conditionalFiles:      []string{"pdb.yaml"},
			deleteConditionalFunc: func() bool { return true },
			createConditionalFunc: func() bool { return true },

			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "abc",
					},
				},
			},
			expectError: true,
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				// We should not see any api call.
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
			},
		},
		{
			name:                  "static resource with no delete conditional and create conditional, creation happens",
			conditionalFiles:      []string{"pdb.yaml"},
			deleteConditionalFunc: nil,
			createConditionalFunc: func() bool { return true },
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("get", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
				if !actions[1].Matches("create", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name:                  "static resource with no delete conditional and false create conditional, no creation",
			conditionalFiles:      []string{"pdb.yaml"},
			deleteConditionalFunc: nil,
			createConditionalFunc: func() bool { return false },
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				// createConditional and deleteConditional are both false.
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
			},
		},
		{
			name:                  "static resource with false delete conditional and false create conditional, no creation",
			conditionalFiles:      []string{"pdb.yaml"},
			deleteConditionalFunc: func() bool { return false },
			createConditionalFunc: func() bool { return false },
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				// Both conditionals are false, so no action.
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
			},
		},
		{
			name:                  "static resource with false delete conditional and false create conditional, existing resource, leave it as is",
			conditionalFiles:      []string{"pdb.yaml"},
			deleteConditionalFunc: func() bool { return false },
			createConditionalFunc: func() bool { return false },
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				// Both conditionals are false, so no action
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
			},
		},
		{
			name: "static resource with true delete conditional and false create conditional, no resource existing, " +
				"deletion is honored, no resource created",
			conditionalFiles:      []string{"pdb.yaml"},
			deleteConditionalFunc: func() bool { return true },
			createConditionalFunc: func() bool { return false },

			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("delete", "poddisruptionbudgets") || actions[0].(clienttesting.GetAction).GetName() != "foo" {
					t.Error(spew.Sdump(actions))
				}
			},
		},
		{
			name: "static resource with true delete conditional and false create conditional, resource existing, " +
				"deletion is honored",
			conditionalFiles:      []string{"pdb.yaml"},
			deleteConditionalFunc: func() bool { return true },
			createConditionalFunc: func() bool { return false },

			existing: []runtime.Object{
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "abc",
					},
				},
			},
			verifyActions: func(actions []clienttesting.Action, t *testing.T) {
				if len(actions) != 1 {
					t.Fatal(spew.Sdump(actions))
				}
				if !actions[0].Matches("delete", "poddisruptionbudgets") {
					t.Error(spew.Sdump(actions))
				}
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cr := conditionalResource{conditionalFiles: tc.conditionalFiles, createConditional: tc.createConditionalFunc, deleteConditional: tc.deleteConditionalFunc}
			coreClient := fakecore.NewSimpleClientset(tc.existing...)
			opInstance := makeFakeOperatorInstance()
			fakeOperatorClient := v1helpers.NewFakeOperatorClient(&opInstance.Spec, &opInstance.Status, nil)
			c := &StaticResourceController{
				name:                   "static-resource-controller",
				manifests:              func(name string) ([]byte, error) { return makePDBManifest(), nil },
				files:                  tc.files,
				conditionalResources:   []conditionalResource{cr},
				ignoreNotFoundOnCreate: false,
				operatorClient:         fakeOperatorClient,
				clients:                (&resourceapply.ClientHolder{}).WithKubernetes(coreClient),
				eventRecorder:          events.NewInMemoryRecorder("test"),
				factory:                nil,
				categoryExpander:       nil,
			}
			err := c.Sync(context.TODO(), factory.NewSyncContext("static-resource-controller",
				events.NewInMemoryRecorder("test")))
			if err != nil && !tc.expectError {
				t.Errorf("failed sync, %v for %v", err, tc.name)
			}
			tc.verifyActions(coreClient.Actions(), t)
		})
	}
}
