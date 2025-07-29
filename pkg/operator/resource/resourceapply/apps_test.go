package resourceapply_test

import (
	"context"
	clocktesting "k8s.io/utils/clock/testing"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
)

func TestApplyDeployment(t *testing.T) {
	tests := []struct {
		name               string
		desiredDeployment  *appsv1.Deployment
		expectedGeneration int64
		actualDeployment   *appsv1.Deployment

		expectError        bool
		expectedUpdate     bool
		expectedDeployment *appsv1.Deployment
	}{
		{
			name:               "the deployment is created because it doesn't exist",
			desiredDeployment:  workload(),
			expectedDeployment: workloadWithDefaultSpecHash(),
			expectedUpdate:     true,
		},

		{
			name:               "the deployment already exists and it's up to date",
			desiredDeployment:  workload(),
			actualDeployment:   workloadWithDefaultSpecHash(),
			expectedDeployment: workloadWithDefaultSpecHash(),
		},

		{
			name:              "the actual deployment was modified by a user and must be updated",
			desiredDeployment: workload(),
			actualDeployment: func() *appsv1.Deployment {
				w := workloadWithDefaultSpecHash()
				w.Generation = 1
				return w
			}(),
			expectedDeployment: func() *appsv1.Deployment {
				w := workloadWithDefaultSpecHash()
				w.Generation = 1 // on a real cluster it would be increased by the server
				return w
			}(),
			expectedUpdate: true,
		},

		{
			name: "the deployment is updated due to a change in the spec",
			desiredDeployment: func() *appsv1.Deployment {
				w := workload()
				w.Spec.Template.Finalizers = []string{"newFinalizer"}
				return w
			}(),
			actualDeployment: workloadWithDefaultSpecHash(),
			expectedDeployment: func() *appsv1.Deployment {
				w := workload()
				w.Annotations["operator.openshift.io/spec-hash"] = "0c4e1cc4d475df8bd73d71d0c56fcf95774c9f4d8bcc676eec369aef3b13a570"
				w.Spec.Template.Finalizers = []string{"newFinalizer"}
				return w
			}(),
			expectedUpdate: true,
		},

		{
			name: "the deployment is updated due to a change in Labels field",
			desiredDeployment: func() *appsv1.Deployment {
				w := workload()
				w.Labels["newLabel"] = "newValue"
				return w
			}(),
			actualDeployment: workloadWithDefaultSpecHash(),
			expectedDeployment: func() *appsv1.Deployment {
				w := workloadWithDefaultSpecHash()
				w.Labels["newLabel"] = "newValue"
				return w
			}(),
			expectedUpdate: true,
		},

		{
			name: "the deployment is updated due to a change in Annotations field",
			desiredDeployment: func() *appsv1.Deployment {
				w := workload()
				w.Annotations["newAnnotation"] = "newValue"
				return w
			}(),
			actualDeployment: workloadWithDefaultSpecHash(),
			expectedDeployment: func() *appsv1.Deployment {
				w := workloadWithDefaultSpecHash()
				w.Annotations["newAnnotation"] = "newValue"
				return w
			}(),
			expectedUpdate: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRecorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
			fakeKubeClient := fake.NewSimpleClientset()
			if tt.actualDeployment != nil {
				fakeKubeClient = fake.NewSimpleClientset(tt.actualDeployment)
			}

			updatedDeployment, updated, err := resourceapply.ApplyDeployment(context.TODO(), fakeKubeClient.AppsV1(), eventRecorder, tt.desiredDeployment, tt.expectedGeneration)
			if tt.expectError && err == nil {
				t.Fatal("expected to get an error")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectedUpdate && !updated {
				t.Fatal("expected ApplyDeployment to report updated=true")
			}
			if !tt.expectedUpdate && updated {
				t.Fatal("expected ApplyDeployment to report updated=false")
			}
			if tt.expectedUpdate && !equality.Semantic.DeepEqual(updatedDeployment, tt.expectedDeployment) {
				t.Errorf("created Deployment is different from the expected one (file) : %s", diff.ObjectDiff(updatedDeployment, tt.expectedDeployment))
			}
		})
	}
}

func TestDeleteDeployment(t *testing.T) {
	validDeployment := workload()
	tests := []struct {
		name               string
		desiredDeployment  *appsv1.Deployment
		deploymentToDelete *appsv1.Deployment
		expectError        bool
		deletedFlag        bool
	}{
		{
			name:               "when deployment exists",
			desiredDeployment:  validDeployment,
			deploymentToDelete: validDeployment,
			expectError:        false,
			deletedFlag:        true,
		},
		{
			name:               "when deployment does not exist",
			deploymentToDelete: validDeployment,
			expectError:        false,
			deletedFlag:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRecorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
			fakeKubeClient := fake.NewSimpleClientset()
			if tt.desiredDeployment != nil {
				fakeKubeClient = fake.NewSimpleClientset(tt.desiredDeployment)
			}
			if tt.desiredDeployment != nil {
				_, _, err := resourceapply.ApplyDeployment(context.TODO(), fakeKubeClient.AppsV1(), eventRecorder, tt.desiredDeployment, 0)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			_, deletedFlag, err := resourceapply.DeleteDeployment(context.TODO(), fakeKubeClient.AppsV1(), eventRecorder, tt.deploymentToDelete)
			if tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if deletedFlag != tt.deletedFlag {
				t.Fatalf("expected deployment to be deleted: %v, got: %v", tt.deletedFlag, deletedFlag)
			}
		})
	}
}

func TestDeleteDaemonSet(t *testing.T) {
	validDaemonSet := daemonSet()
	tests := []struct {
		name              string
		desiredDaemonSet  *appsv1.DaemonSet
		daemonsetToDelete *appsv1.DaemonSet
		deletedFlag       bool
		expectError       bool
	}{
		{
			name:              "when daemonset exists",
			desiredDaemonSet:  validDaemonSet,
			daemonsetToDelete: validDaemonSet,
			deletedFlag:       true,
			expectError:       false,
		},
		{
			name:              "when daemonset does not exist",
			daemonsetToDelete: validDaemonSet,
			deletedFlag:       false,
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRecorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
			fakeKubeClient := fake.NewSimpleClientset()
			if tt.desiredDaemonSet != nil {
				fakeKubeClient = fake.NewSimpleClientset(tt.desiredDaemonSet)
			}
			if tt.desiredDaemonSet != nil {
				_, _, err := resourceapply.ApplyDaemonSet(context.TODO(), fakeKubeClient.AppsV1(), eventRecorder, tt.desiredDaemonSet, 0)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			_, deletedFlag, err := resourceapply.DeleteDaemonSet(context.TODO(), fakeKubeClient.AppsV1(), eventRecorder, tt.daemonsetToDelete)
			if tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if deletedFlag != tt.deletedFlag {
				t.Fatalf("expected daemonset to be deleted: %v, got: %v", tt.deletedFlag, deletedFlag)
			}
		})
	}
}

func TestApplyDeploymentWithForce(t *testing.T) {
	tests := []struct {
		name               string
		desiredDeployment  *appsv1.Deployment
		expectedGeneration int64
		actualDeployment   *appsv1.Deployment
		forceRollout       bool

		expectError        bool
		expectedUpdate     bool
		expectedDeployment *appsv1.Deployment
	}{
		{
			name:               "the deployment is created with the pull-spec annotation because it doesn't exist",
			desiredDeployment:  workload(),
			expectedDeployment: workloadWithDefaultPullSpec(),
			expectedUpdate:     true,
		},

		{
			name:               "the deployment is updated when forceRollout flag is set",
			desiredDeployment:  workload(),
			actualDeployment:   workloadWithDefaultPullSpec(),
			expectedDeployment: workloadWithDefaultPullSpec(),
			expectedUpdate:     true,
			forceRollout:       true,
		},

		{
			name:              "the deployment is up to date and forceRollout is set to false",
			desiredDeployment: workload(),
			actualDeployment:  workloadWithDefaultPullSpec(),
			expectedUpdate:    false,
		},

		{
			name: "the deployment is NOT updated due to a change in the spec",
			desiredDeployment: func() *appsv1.Deployment {
				w := workload()
				w.Spec.Template.Finalizers = []string{"newFinalizer"}
				return w
			}(),
			actualDeployment: workloadWithDefaultPullSpec(),
			expectedUpdate:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventRecorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
			fakeKubeClient := fake.NewSimpleClientset()
			if tt.actualDeployment != nil {
				fakeKubeClient = fake.NewSimpleClientset(tt.actualDeployment)
			}

			updatedDeployment, updated, err := resourceapply.ApplyDeploymentWithForce(context.TODO(), fakeKubeClient.AppsV1(), eventRecorder, tt.desiredDeployment, tt.expectedGeneration, tt.forceRollout)
			if tt.expectError && err == nil {
				t.Fatal("expected to get an error")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectedUpdate && !updated {
				t.Fatal("expected ApplyDeploymentWithForce to report updated=true")
			}
			if !tt.expectedUpdate && updated {
				t.Fatal("expected ApplyDeploymentWithForce to report updated=false")
			}
			if tt.forceRollout {
				tt.expectedDeployment.Annotations["operator.openshift.io/force"] = updatedDeployment.Annotations["operator.openshift.io/force"]
				tt.expectedDeployment.Spec.Template.Annotations["operator.openshift.io/force"] = updatedDeployment.Spec.Template.Annotations["operator.openshift.io/force"]
			}
			if tt.expectedUpdate && !equality.Semantic.DeepEqual(updatedDeployment, tt.expectedDeployment) {
				t.Errorf("created Deployment is different from the expected one (file) : %s", diff.ObjectDiff(updatedDeployment, tt.expectedDeployment))
			}
		})
	}
}

func workload() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "apiserver",
			Namespace:   "openshift-apiserver",
			Labels:      map[string]string{},
			Annotations: map[string]string{},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](3),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{},
					Annotations: map[string]string{},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Image: "docker-registry/img",
						},
					},
				},
			},
		},
	}
}

func daemonSet() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "apiserver",
			Namespace:   "openshift-apiserver",
			Labels:      map[string]string{},
			Annotations: map[string]string{},
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{},
					Annotations: map[string]string{},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Image: "docker-registry/img",
						},
					},
				},
			},
		},
	}
}

func workloadWithDefaultSpecHash() *appsv1.Deployment {
	w := workload()
	w.Annotations["operator.openshift.io/spec-hash"] = "1c48130600d2fc7512e0f327dc696bd279f5442b840a6df66c3fd0be33564de2"
	return w
}

func workloadWithDefaultPullSpec() *appsv1.Deployment {
	w := workload()
	w.Annotations["operator.openshift.io/pull-spec"] = w.Spec.Template.Spec.Containers[0].Image
	return w
}
