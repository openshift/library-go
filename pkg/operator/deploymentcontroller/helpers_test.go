package deploymentcontroller

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreinformers "k8s.io/client-go/informers"
	fakecore "k8s.io/client-go/kubernetes/fake"
)

type deploymentModifier func(*appsv1.Deployment) *appsv1.Deployment

func makeDeployment(modifiers ...deploymentModifier) *appsv1.Deployment {
	manifest := makeFakeManifest()
	dep := resourceread.ReadDeploymentV1OrDie(manifest)

	var one int32 = 1
	dep.Spec.Replicas = &one

	for _, modifier := range modifiers {
		dep = modifier(dep)
	}

	return dep
}

func makeNode(suffix string, labels map[string]string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("node-%s", suffix),
			Labels: labels,
		},
	}
}

func withDeploymentReplicas(replicas int32) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		instance.Spec.Replicas = &replicas
		return instance
	}
}

func withDeploymentImage(image string) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		instance.Spec.Template.Spec.Containers[0].Image = image
		return instance
	}
}

func withDeploymentGeneration(generations ...int64) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		instance.Generation = generations[0]
		if len(generations) > 1 {
			instance.Status.ObservedGeneration = generations[1]
		}
		return instance
	}
}

func withDeploymentConditions(conditionType appsv1.DeploymentConditionType, reason string, status v1.ConditionStatus) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		instance.Status.Conditions = append(instance.Status.Conditions, appsv1.DeploymentCondition{
			Type:   conditionType,
			Status: status,
			Reason: reason,
		})
		return instance
	}
}

func TestWithReplicasHook(t *testing.T) {
	var (
		masterNodeLabels = map[string]string{"node-role.kubernetes.io/master": ""}
		workerNodeLabels = map[string]string{"node-role.kubernetes.io/worker": ""}
	)
	testCases := []struct {
		name               string
		initialOperator    *fakeOperatorInstance
		initialNodes       []*v1.Node
		initialDeployment  *appsv1.Deployment
		expectedDeployment *appsv1.Deployment
		expectError        bool
	}{
		{
			name:            "three-node control-plane",
			initialOperator: makeFakeOperatorInstance(),
			initialNodes: []*v1.Node{
				makeNode("A", masterNodeLabels),
				makeNode("B", masterNodeLabels),
				makeNode("C", masterNodeLabels),
			},
			initialDeployment: makeDeployment(
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment(
				withDeploymentReplicas(3),
				withDeploymentGeneration(1, 0)),
			expectError: false,
		},
		{
			name:            "three-node control-plane with one worker node",
			initialOperator: makeFakeOperatorInstance(),
			initialNodes: []*v1.Node{
				makeNode("A", masterNodeLabels),
				makeNode("B", masterNodeLabels),
				makeNode("C", masterNodeLabels),
				makeNode("D", workerNodeLabels),
			},
			initialDeployment: makeDeployment(
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment(
				withDeploymentReplicas(3),
				withDeploymentGeneration(1, 0)),
			expectError: false,
		},
		{
			name:            "two-node control-plane",
			initialOperator: makeFakeOperatorInstance(),
			initialNodes: []*v1.Node{
				makeNode("A", masterNodeLabels),
				makeNode("B", masterNodeLabels),
			},
			initialDeployment: makeDeployment(
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment(
				withDeploymentReplicas(2),
				withDeploymentGeneration(1, 0)),
			expectError: false,
		},
		{
			name:            "single-node control-plane with one worker node",
			initialOperator: makeFakeOperatorInstance(),
			initialNodes: []*v1.Node{
				makeNode("A", masterNodeLabels),
				makeNode("B", workerNodeLabels),
			},
			initialDeployment: makeDeployment(
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment(
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0)),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var initialObjects []runtime.Object

			// Add deployment to slice of objects to be added to client and informer
			initialObjects = append(initialObjects, tc.initialDeployment)

			// Do the same with nodes
			for _, node := range tc.initialNodes {
				initialObjects = append(initialObjects, node)
			}

			// Create fake client and informer
			coreClient := fakecore.NewSimpleClientset(initialObjects...)
			coreInformerFactory := coreinformers.NewSharedInformerFactory(coreClient, 0 /*no resync */)

			// Fill the fake informer with the initial deployment and nodes
			coreInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(tc.initialDeployment)
			for _, node := range initialObjects {
				coreInformerFactory.Core().V1().Nodes().Informer().GetIndexer().Add(node)
			}

			fn := WithReplicasHook(coreInformerFactory.Core().V1().Nodes().Lister())
			err := fn(&tc.initialOperator.Spec, tc.initialDeployment)
			if err != nil && !tc.expectError {
				t.Errorf("Expected no error running hook function, got: %v", err)

			}
			if !equality.Semantic.DeepEqual(tc.initialDeployment, tc.expectedDeployment) {
				t.Errorf("Unexpected Deployment content:\n%s", cmp.Diff(tc.initialDeployment, tc.expectedDeployment))
			}
		})
	}
}

func TestWithImageHook(t *testing.T) {
	testCases := []struct {
		name               string
		initialOperator    *fakeOperatorInstance
		initialDeployment  *appsv1.Deployment
		image              string
		expectedDeployment *appsv1.Deployment
		expectError        bool
	}{
		{
			name:            "check if image is properly updated",
			initialOperator: makeFakeOperatorInstance(),
			image:           "quay.io/openshift/origin-test-csi-driver:latest",
			initialDeployment: makeDeployment(
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment(
				withDeploymentReplicas(1),
				withDeploymentImage("quay.io/openshift/origin-test-csi-driver:latest"),
				withDeploymentGeneration(1, 0)),
			expectError: false,
		},
		{
			name:            "empty image, we except and error",
			initialOperator: makeFakeOperatorInstance(),
			image:           "",
			initialDeployment: makeDeployment(
				withDeploymentReplicas(1),
				withDeploymentGeneration(1, 0)),
			expectedDeployment: makeDeployment(
				withDeploymentReplicas(1),
				withDeploymentImage(""),
				withDeploymentGeneration(1, 0)),
			expectError: true,
		},
	}
	for _, tc := range testCases {
		os.Setenv("CLI_IMAGE", tc.image)
		fn := WithImageHook()
		err := fn(&tc.initialOperator.Spec, tc.initialDeployment)
		if err != nil && !tc.expectError {
			t.Errorf("Expected no error running hook function, got: %v", err)
		}
		if tc.expectedDeployment.Spec.Template.Spec.Containers[0].Image != tc.image {
			t.Errorf("Unexpected Deployment content:\n%s", cmp.Diff(tc.initialDeployment, tc.expectedDeployment))
		}
	}
}
