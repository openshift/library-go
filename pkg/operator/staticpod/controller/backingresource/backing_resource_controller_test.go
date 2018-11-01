package backingresource

import (
	"testing"
	"time"

	"k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"github.com/openshift/library-go/pkg/operator/staticpod/controller/common"
)

func TestNewBackingResourceController(t *testing.T) {
	kubeClient := fake.NewSimpleClientset()
	var (
		serviceAccountCreated     *v1.ServiceAccount
		clusterRoleBindingCreated *rbacv1.ClusterRoleBinding
		createCallCount           int
	)
	kubeClient.PrependReactor("*", "*", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
		createAction, ok := action.(ktesting.CreateAction)
		if ok {
			if createAction.GetResource().Resource == "serviceaccounts" {
				createCallCount += 1
				serviceAccountCreated = createAction.GetObject().(*v1.ServiceAccount)
			}
			if createAction.GetResource().Resource == "clusterrolebindings" {
				createCallCount += 1
				clusterRoleBindingCreated = createAction.GetObject().(*rbacv1.ClusterRoleBinding)
			}
		}
		return false, nil, nil
	})
	kubeInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("test"))

	fakeStaticPodOperatorClient := common.NewFakeStaticPodOperatorClient(
		&operatorv1alpha1.OperatorSpec{
			ManagementState: operatorv1alpha1.Managed,
			Version:         "3.11.1",
		},
		&operatorv1alpha1.OperatorStatus{},
		&operatorv1alpha1.StaticPodOperatorStatus{
			LatestAvailableDeploymentGeneration: 1,
			NodeStatuses: []operatorv1alpha1.NodeStatus{
				{
					NodeName:                    "test-node-1",
					CurrentDeploymentGeneration: 0,
					TargetDeploymentGeneration:  0,
				},
			},
		},
		nil,
	)

	c := NewBackingResourceController(
		"test",
		fakeStaticPodOperatorClient,
		kubeInformers,
		kubeClient,
	)

	if err := c.sync(); err != nil {
		t.Fatal(err)
	}

	if createCallCount != 2 {
		t.Fatalf("expected 2 create calls, got %d", createCallCount)
	}

	if serviceAccountCreated == nil {
		t.Fatal("expected service account to be created")
	}
	if clusterRoleBindingCreated == nil {
		t.Fatal("expected cluster role binding to be created")
	}

	if serviceAccountCreated.Namespace != "test" {
		t.Fatalf("expected that service account have 'test' namespace, got %q", serviceAccountCreated.Namespace)
	}

	if clusterRoleBindingCreated.Name != "system:openshift:operator:test-installer" {
		t.Fatalf("expected that cluster role binding name is 'system:openshift:operator:test-installer', got %q", clusterRoleBindingCreated.Name)
	}

	if clusterRoleBindingCreated.Subjects[0].Namespace != "test" {
		t.Fatalf("expected that cluster role binding namespace is 'test', got %q", clusterRoleBindingCreated.Subjects[0].Namespace)
	}

	if err := c.sync(); err != nil {
		t.Fatal(err)
	}

	if createCallCount != 2 {
		t.Fatalf("expected no create calls after next sync, got %d", createCallCount)
	}
}
