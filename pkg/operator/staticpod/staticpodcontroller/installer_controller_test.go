package staticpodcontroller

import (
	"errors"
	"testing"
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
)

func TestNewNodeStateForInstallInProgress(t *testing.T) {
	kubeClient := fake.NewSimpleClientset()

	var (
		installerPod   *v1.Pod
		createPodCount int
	)

	kubeClient.PrependReactor("create", "pods", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
		installerPod = action.(ktesting.CreateAction).GetObject().(*v1.Pod)
		createPodCount += 1
		return false, nil, nil
	})

	kubeInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("test"))

	fakeStaticPodOperatorClient := &staticPodOperatorClient{
		fakeOperatorSpec: &operatorv1alpha1.OperatorSpec{
			ManagementState: operatorv1alpha1.Managed,
			Version:         "3.11.1",
		},
		fakeOperatorStatus: &operatorv1alpha1.OperatorStatus{},
		fakeStaticPodOperatorStatus: &operatorv1alpha1.StaticPodOperatorStatus{
			LatestAvailableDeploymentGeneration: 1,
			NodeStatuses: []operatorv1alpha1.NodeStatus{
				{
					NodeName:                    "test-node-1",
					CurrentDeploymentGeneration: 0,
					TargetDeploymentGeneration:  0,
				},
			},
		},
		t:               t,
		resourceVersion: "0",
	}

	c := NewInstallerController(
		"test",
		[]string{"test-config"},
		[]string{"test-secret"},
		[]string{"/bin/true"},
		kubeInformers,
		fakeStaticPodOperatorClient,
		kubeClient,
	)
	c.installerPodImageFn = func() string { return "docker.io/foo/bar" }

	if err := c.sync(); err != nil {
		t.Fatal(err)
	}

	if installerPod == nil {
		t.Fatalf("expected to create installer pod")
	}

	fakeStaticPodOperatorClient.fakeStaticPodOperatorStatus.NodeStatuses[0].TargetDeploymentGeneration = 1

	if err := c.sync(); err != nil {
		t.Fatal(err)
	}

	if createPodCount != 1 {
		t.Fatalf("was not expecting to create new installer pod")
	}

	installerPod.Status.Phase = v1.PodSucceeded
	kubeClient.PrependReactor("get", "pods", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, installerPod, nil
	})

	if err := c.sync(); err != nil {
		t.Fatal(err)
	}

	if generation := fakeStaticPodOperatorClient.fakeStaticPodOperatorStatus.NodeStatuses[0].CurrentDeploymentGeneration; generation != 1 {
		t.Errorf("expected current deployment generation for node to be 1, got %d", generation)
	}

	fakeStaticPodOperatorClient.fakeStaticPodOperatorStatus.LatestAvailableDeploymentGeneration = 2
	fakeStaticPodOperatorClient.fakeStaticPodOperatorStatus.NodeStatuses[0].TargetDeploymentGeneration = 2
	fakeStaticPodOperatorClient.fakeStaticPodOperatorStatus.NodeStatuses[0].CurrentDeploymentGeneration = 1
	installerPod.Status.Phase = v1.PodFailed
	installerPod.Status.ContainerStatuses = []v1.ContainerStatus{
		{
			Name: "installer",
			State: v1.ContainerState{
				Terminated: &v1.ContainerStateTerminated{Message: "fake death"},
			},
		},
	}
	if err := c.sync(); err != nil {
		t.Fatal(err)
	}
	if generation := fakeStaticPodOperatorClient.fakeStaticPodOperatorStatus.NodeStatuses[0].LastFailedDeploymentGeneration; generation != 2 {
		t.Errorf("expected last failed deployment generation for node to be 2, got %d", generation)
	}

	if errors := fakeStaticPodOperatorClient.fakeStaticPodOperatorStatus.NodeStatuses[0].LastFailedDeploymentErrors; len(errors) > 0 {
		if errors[0] != "installer: fake death" {
			t.Errorf("expected the error to be set to 'fake death', got %#v", errors)
		}
	} else {
		t.Errorf("expected errors to be not empty")
	}
}

func TestCreateInstallerPod(t *testing.T) {
	kubeClient := fake.NewSimpleClientset()

	var installerPod *v1.Pod
	kubeClient.PrependReactor("create", "pods", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
		installerPod = action.(ktesting.CreateAction).GetObject().(*v1.Pod)
		return false, nil, nil
	})
	kubeInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("test"))

	fakeStaticPodOperatorClient := &staticPodOperatorClient{
		fakeOperatorSpec: &operatorv1alpha1.OperatorSpec{
			ManagementState: operatorv1alpha1.Managed,
			Version:         "3.11.1",
		},
		fakeOperatorStatus: &operatorv1alpha1.OperatorStatus{},
		fakeStaticPodOperatorStatus: &operatorv1alpha1.StaticPodOperatorStatus{
			LatestAvailableDeploymentGeneration: 1,
			NodeStatuses: []operatorv1alpha1.NodeStatus{
				{
					NodeName:                    "test-node-1",
					CurrentDeploymentGeneration: 0,
					TargetDeploymentGeneration:  0,
				},
			},
		},
		t:               t,
		resourceVersion: "0",
	}

	c := NewInstallerController(
		"test",
		[]string{"test-config"},
		[]string{"test-secret"},
		[]string{"/bin/true"},
		kubeInformers,
		fakeStaticPodOperatorClient,
		kubeClient,
	)
	c.installerPodImageFn = func() string { return "docker.io/foo/bar" }
	if err := c.sync(); err != nil {
		t.Fatal(err)
	}

	if installerPod == nil {
		t.Fatalf("expected to create installer pod")
	}

	if installerPod.Spec.Containers[0].Image != "docker.io/foo/bar" {
		t.Fatalf("expected docker.io/foo/bar image, got %q", installerPod.Spec.Containers[0].Image)
	}

	if installerPod.Spec.Containers[0].Command[0] != "/bin/true" {
		t.Fatalf("expected /bin/true as a command, got %q", installerPod.Spec.Containers[0].Command[0])
	}

	if installerPod.Name != "installer-1-test-node-1" {
		t.Fatalf("expected name installer-1-test-node-1, got %q", installerPod.Name)
	}

	if installerPod.Namespace != "test" {
		t.Fatalf("expected test namespace, got %q", installerPod.Namespace)
	}

	expectedArgs := []string{
		"-v=0",
		"--deployment-id=1",
		"--namespace=test",
		"--pod=test-config",
		"--resource-dir=/etc/kubernetes/static-pod-resources",
		"--pod-manifest-dir=/etc/kubernetes/manifests",
		"--configmaps=test-config",
		"--secrets=test-secret",
	}

	if len(expectedArgs) != len(installerPod.Spec.Containers[0].Args) {
		t.Fatalf("expected arguments does not match container arguments: %#v != %#v", expectedArgs, installerPod.Spec.Containers[0].Args)
	}

	for i, v := range installerPod.Spec.Containers[0].Args {
		if expectedArgs[i] != v {
			t.Errorf("arg[%d] expected %q, got %q", i, expectedArgs[i], v)
		}
	}

	fakeStaticPodOperatorClient.triggerStatusUpdateError = errors.New("test error")
	if err := c.sync(); err == nil {
		t.Error("expected to trigger an error on status update")
	}
}

type staticPodOperatorClient struct {
	fakeOperatorSpec            *operatorv1alpha1.OperatorSpec
	fakeOperatorStatus          *operatorv1alpha1.OperatorStatus
	fakeStaticPodOperatorStatus *operatorv1alpha1.StaticPodOperatorStatus
	resourceVersion             string
	triggerStatusUpdateError    error
	t                           *testing.T
}

type fakeSharedIndexInformer struct{}

func (fakeSharedIndexInformer) AddEventHandler(handler cache.ResourceEventHandler) {
}

func (fakeSharedIndexInformer) AddEventHandlerWithResyncPeriod(handler cache.ResourceEventHandler, resyncPeriod time.Duration) {
}

func (fakeSharedIndexInformer) GetStore() cache.Store {
	panic("implement me")
}

func (fakeSharedIndexInformer) GetController() cache.Controller {
	panic("implement me")
}

func (fakeSharedIndexInformer) Run(stopCh <-chan struct{}) {
	panic("implement me")
}

func (fakeSharedIndexInformer) HasSynced() bool {
	panic("implement me")
}

func (fakeSharedIndexInformer) LastSyncResourceVersion() string {
	panic("implement me")
}

func (fakeSharedIndexInformer) AddIndexers(indexers cache.Indexers) error {
	panic("implement me")
}

func (fakeSharedIndexInformer) GetIndexer() cache.Indexer {
	panic("implement me")
}

func (c *staticPodOperatorClient) Informer() cache.SharedIndexInformer {
	return &fakeSharedIndexInformer{}
}

func (c *staticPodOperatorClient) Get() (*operatorv1alpha1.OperatorSpec, *operatorv1alpha1.StaticPodOperatorStatus, string, error) {
	return c.fakeOperatorSpec, c.fakeStaticPodOperatorStatus, "1", nil
}

func (c *staticPodOperatorClient) UpdateStatus(resourceVersion string, status *operatorv1alpha1.StaticPodOperatorStatus) (*operatorv1alpha1.StaticPodOperatorStatus, error) {
	// c.t.Logf("Calling UpdateStatus(): %#v", spew.Sdump(*status))
	c.resourceVersion = resourceVersion
	c.fakeStaticPodOperatorStatus = status
	return c.fakeStaticPodOperatorStatus, c.triggerStatusUpdateError
}

func (c *staticPodOperatorClient) CurrentStatus() (operatorv1alpha1.OperatorStatus, error) {
	return *c.fakeOperatorStatus, nil
}
