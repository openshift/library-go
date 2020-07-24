package resourceapply_test

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/pointer"

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
				w.Annotations["operator.openshift.io/spec-hash"] = "5322a9feed3671ec5e7bc72c86c9b7e2f628b00e9c7c8c4c93a48ee63e8db47a"
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
			eventRecorder := events.NewInMemoryRecorder("")
			fakeKubeClient := fake.NewSimpleClientset()
			if tt.actualDeployment != nil {
				fakeKubeClient = fake.NewSimpleClientset(tt.actualDeployment)
			}

			updatedDeployment, updated, err := resourceapply.ApplyDeployment(fakeKubeClient.AppsV1(), eventRecorder, tt.desiredDeployment, tt.expectedGeneration)
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
			eventRecorder := events.NewInMemoryRecorder("")
			fakeKubeClient := fake.NewSimpleClientset()
			if tt.actualDeployment != nil {
				fakeKubeClient = fake.NewSimpleClientset(tt.actualDeployment)
			}

			updatedDeployment, updated, err := resourceapply.ApplyDeploymentWithForce(fakeKubeClient.AppsV1(), eventRecorder, tt.desiredDeployment, tt.expectedGeneration, tt.forceRollout)
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
			Replicas: pointer.Int32Ptr(3),
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
	w.Annotations["operator.openshift.io/spec-hash"] = "32a23216b08c6b04f6c367de919931543f2620ea68e1eee5f5ef203b533d99aa"
	return w
}

func workloadWithDefaultPullSpec() *appsv1.Deployment {
	w := workload()
	w.Annotations["operator.openshift.io/pull-spec"] = w.Spec.Template.Spec.Containers[0].Image
	return w
}
