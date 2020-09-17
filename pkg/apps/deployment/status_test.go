package deployment

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	v1 "k8s.io/client-go/listers/core/v1"
)

func makeDeployment(namespace string, labels map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
			},
		},
	}
}

func makePod(mutateFn func(pod *corev1.Pod)) *corev1.Pod {
	pod := &corev1.Pod{}
	pod.Name = "test"
	mutateFn(pod)
	return pod
}

type fakePodLister struct {
	pods []*corev1.Pod
}

func (f *fakePodLister) List(selector labels.Selector) ([]*corev1.Pod, error) {
	panic("implement me")
}

func (f *fakePodLister) Pods(namespace string) v1.PodNamespaceLister {
	return &fakePodNamespacer{
		pods: f.pods,
	}
}

type fakePodNamespacer struct {
	pods []*corev1.Pod
}

func (f *fakePodNamespacer) List(selector labels.Selector) ([]*corev1.Pod, error) {
	return f.pods, nil
}

func (f *fakePodNamespacer) Get(name string) (*corev1.Pod, error) {
	panic("implement me")
}

func TestPodContainersStatus(t *testing.T) {
	var (
		defaultLabels = map[string]string{"app": "test"}
	)
	tests := []struct {
		name             string
		pods             []*corev1.Pod
		deployment       *appsv1.Deployment
		expectedMessages []string
		expectedError    error
	}{
		{
			name: "ready with one restart",
			pods: append([]*corev1.Pod{}, makePod(func(pod *corev1.Pod) {
				pod.Labels = defaultLabels
				pod.Status.Phase = corev1.PodRunning
				pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
					Name:         "test",
					RestartCount: 1,
					Ready:        true,
				})
			})),
			deployment:       makeDeployment("foo", defaultLabels),
			expectedMessages: []string{},
		},
		{
			name: "not ready with one restart",
			pods: append([]*corev1.Pod{}, makePod(func(pod *corev1.Pod) {
				pod.Labels = defaultLabels
				pod.Status.Phase = corev1.PodRunning
				pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
					Name:         "test",
					RestartCount: 1,
				})
			})),
			deployment:       makeDeployment("foo", defaultLabels),
			expectedMessages: []string{"container is not ready in test pod"},
		},
		{
			name: "not ready with two restarts",
			pods: append([]*corev1.Pod{}, makePod(func(pod *corev1.Pod) {
				pod.Labels = defaultLabels
				pod.Status.Phase = corev1.PodRunning
				pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
					Name:         "test",
					RestartCount: 2,
				})
			})),
			deployment:       makeDeployment("foo", defaultLabels),
			expectedMessages: []string{"container is crashlooping in test pod"},
		},
		{
			name: "not ready and stucked in waiting",
			pods: append([]*corev1.Pod{}, makePod(func(pod *corev1.Pod) {
				pod.Labels = defaultLabels
				pod.Status.Phase = corev1.PodPending
				pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
					Name: "test",
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason:  "IsSlow",
							Message: "Slow container",
						},
					},
				})
			})),
			deployment:       makeDeployment("foo", defaultLabels),
			expectedMessages: []string{"container is waiting in pending test pod"},
		},
		{
			name: "not ready stucked in waiting and crashlooping",
			pods: append([]*corev1.Pod{}, makePod(func(pod *corev1.Pod) {
				pod.Labels = defaultLabels
				pod.Status.Phase = corev1.PodPending
				pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
					Name:         "test",
					RestartCount: 5,
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason:  "IsSlow",
							Message: "Slow container",
						},
					},
				})
			})),
			deployment:       makeDeployment("foo", defaultLabels),
			expectedMessages: []string{"crashlooping container is waiting in pending test pod"},
		},
		{
			name: "not ready and terminated non-gracefully",
			pods: append([]*corev1.Pod{}, makePod(func(pod *corev1.Pod) {
				pod.Labels = defaultLabels
				pod.Status.Phase = corev1.PodFailed
				pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
					Name:         "test",
					RestartCount: 5,
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: 1,
							Reason:   "Killed",
							Message:  "Killed",
						},
					},
				})
			})),
			deployment:       makeDeployment("foo", defaultLabels),
			expectedMessages: []string{"container is crashed in test pod"},
		},

		{
			name: "two containers crashed",
			pods: append([]*corev1.Pod{}, makePod(func(pod *corev1.Pod) {
				pod.Labels = defaultLabels
				pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
					Name:         "one",
					RestartCount: 5,
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: 1,
							Reason:   "Killed",
							Message:  "Killed",
						},
					},
				},
					corev1.ContainerStatus{
						Name:         "second",
						RestartCount: 5,
						State: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{
								ExitCode: 1,
								Reason:   "Killed",
								Message:  "Killed",
							},
						},
					},
				)
			})),
			deployment:       makeDeployment("foo", defaultLabels),
			expectedMessages: []string{"2 containers are crashed in test pod"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			podLister := &fakePodLister{
				pods: test.pods,
			}
			messages, err := PodContainersStatus(test.deployment, podLister)
			if test.expectedError != nil && !errors.Is(err, test.expectedError) {
				t.Fatalf("expected error %v, got %v", test.expectedError, err)
			}
			if test.expectedError == nil && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if !reflect.DeepEqual(messages, test.expectedMessages) {
				t.Fatalf("expected messages:\n%s\n\ngot:\n\n%s\n", strings.Join(test.expectedMessages, "\n"), strings.Join(messages, "\n"))
			}
		})
	}
}
