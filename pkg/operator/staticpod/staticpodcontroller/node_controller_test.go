package staticpodcontroller

import (
	"fmt"
	"testing"
	"time"

	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

func fakeMasterNode(name string) *v1.Node {
	n := &v1.Node{}
	n.Name = name
	n.Labels = map[string]string{
		"node-role.kubernetes.io/master": "",
	}

	return n
}

func TestNewNodeController(t *testing.T) {
	tests := []struct {
		name               string
		startNodes         []runtime.Object
		startNodeStatus    []operatorv1alpha1.NodeStatus
		evaluateNodeStatus func([]operatorv1alpha1.NodeStatus) error
	}{
		{
			name:       "single-node",
			startNodes: []runtime.Object{fakeMasterNode("test-node-1")},
			evaluateNodeStatus: func(s []operatorv1alpha1.NodeStatus) error {
				if len(s) != 1 {
					return fmt.Errorf("expected 1 node status, got %d", len(s))
				}
				if s[0].NodeName != "test-node-1" {
					return fmt.Errorf("expected 'test-node-1' as node name, got %q", s[0].NodeName)
				}
				return nil
			},
		},
		{
			name:       "multi-node",
			startNodes: []runtime.Object{fakeMasterNode("test-node-1"), fakeMasterNode("test-node-2"), fakeMasterNode("test-node-3")},
			startNodeStatus: []operatorv1alpha1.NodeStatus{
				{
					NodeName: "test-node-1",
				},
			},
			evaluateNodeStatus: func(s []operatorv1alpha1.NodeStatus) error {
				if len(s) != 3 {
					return fmt.Errorf("expected 3 node status, got %d", len(s))
				}
				if s[0].NodeName != "test-node-1" {
					return fmt.Errorf("expected first node to be test-node-1, got %q", s[0].NodeName)
				}
				if s[1].NodeName != "test-node-2" {
					return fmt.Errorf("expected second node to be test-node-2, got %q", s[1].NodeName)
				}
				return nil
			},
		},
		{
			name:       "single-node-removed",
			startNodes: []runtime.Object{},
			startNodeStatus: []operatorv1alpha1.NodeStatus{
				{
					NodeName: "lost-node",
				},
			},
			evaluateNodeStatus: func(s []operatorv1alpha1.NodeStatus) error {
				if len(s) != 0 {
					return fmt.Errorf("expected no node status, got %d", len(s))
				}
				return nil
			},
		},
		{
			name:       "no-op",
			startNodes: []runtime.Object{fakeMasterNode("test-node-1")},
			startNodeStatus: []operatorv1alpha1.NodeStatus{
				{
					NodeName: "test-node-1",
				},
			},
			evaluateNodeStatus: func(s []operatorv1alpha1.NodeStatus) error {
				if len(s) != 1 {
					return fmt.Errorf("expected one node status, got %d", len(s))
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset(test.startNodes...)
			fakeLister := &fakeNodeLister{client: kubeClient}
			kubeInformers := informers.NewSharedInformerFactory(kubeClient, 1*time.Minute)
			fakeStaticPodOperatorClient := &fakeStaticPodOperatorClient{
				fakeOperatorSpec: &operatorv1alpha1.OperatorSpec{
					ManagementState: operatorv1alpha1.Managed,
					Version:         "3.11.1",
				},
				fakeOperatorStatus: &operatorv1alpha1.OperatorStatus{},
				fakeStaticPodOperatorStatus: &operatorv1alpha1.StaticPodOperatorStatus{
					LatestAvailableDeploymentGeneration: 1,
					NodeStatuses:                        test.startNodeStatus,
				},
				t:               t,
				resourceVersion: "0",
			}

			c := NewNodeController(fakeStaticPodOperatorClient, kubeInformers)
			// override the lister so we don't have to run the informer to list nodes
			c.nodeLister = fakeLister
			if err := c.sync(); err != nil {
				t.Fatal(err)
			}

			if err := test.evaluateNodeStatus(fakeStaticPodOperatorClient.fakeStaticPodOperatorStatus.NodeStatuses); err != nil {
				t.Errorf("%s: failed to evaluate node status: %v", test.name, err)
			}
		})

	}
}
