package onepodpernodeccontroller

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func mustTime(in string) time.Time {
	out, err := time.Parse(time.RFC3339, in)
	if err != nil {
		panic(err)
	}
	return out
}

type podMutator func(pod *corev1.Pod) *corev1.Pod

func createPod(pod *corev1.Pod, mutators ...podMutator) *corev1.Pod {
	for _, mutator := range mutators {
		pod = mutator(pod)
	}
	return pod
}

func newPod(namespace, name string, creationTime time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         namespace,
			Name:              name,
			CreationTimestamp: metav1.Time{Time: creationTime},
		},
	}
}

func setLabel(key, value string) podMutator {
	return func(pod *corev1.Pod) *corev1.Pod {
		if pod.Labels == nil {
			pod.Labels = map[string]string{}
		}
		pod.Labels[key] = value
		return pod
	}
}

func setNode(nodeName string) podMutator {
	return func(pod *corev1.Pod) *corev1.Pod {
		pod.Spec.NodeName = nodeName
		return pod
	}
}

func makeReadyAt(time time.Time) podMutator {
	return func(pod *corev1.Pod) *corev1.Pod {
		pod.Status.Conditions = append(pod.Status.Conditions,
			corev1.PodCondition{
				Type:               corev1.PodReady,
				Status:             corev1.ConditionTrue,
				LastTransitionTime: metav1.Time{Time: time},
			},
		)
		return pod
	}
}

func setDeleted(time time.Time) podMutator {
	return func(pod *corev1.Pod) *corev1.Pod {
		pod.DeletionTimestamp = &metav1.Time{Time: time}
		return pod
	}
}

func TestOnePodPerNodeController_syncManaged(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(mustTime("2022-03-07T12:00:00Z"))
	twoHoursAgo := fakeClock.Now().Add(-2 * time.Hour)
	oneHourAgo := fakeClock.Now().Add(-1 * time.Hour)
	oneMinuteAgo := fakeClock.Now().Add(-1 * time.Minute)
	oneSecondAgo := fakeClock.Now().Add(-1 * time.Second)

	type fields struct {
		name            string
		operatorClient  v1helpers.OperatorClientWithFinalizers
		namespace       string
		pods            []*corev1.Pod
		podSelector     labels.Selector
		minReadySeconds int32
		recorder        events.Recorder
	}
	type args struct {
		ctx         context.Context
		syncContext factory.SyncContext
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		wantErr         bool
		validateActions func(clientset *fake.Clientset) error
	}{
		{
			name: "no-evict-all-spread",
			fields: fields{
				operatorClient: nil,
				namespace:      "test-ns",
				pods: []*corev1.Pod{
					createPod(
						newPod("test-ns", "first", twoHoursAgo),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneHourAgo.Add(time.Minute)),
					),
					createPod(
						newPod("test-ns", "second", oneHourAgo),
						setLabel("label-1", "match"),
						setNode("node-2"),
						makeReadyAt(oneHourAgo.Add(time.Minute)),
					),
				},
				podSelector:     labels.Set{"label-1": "match"}.AsSelector(),
				minReadySeconds: 10,
				recorder:        events.NewInMemoryRecorder("testing"),
			},
			args:    args{},
			wantErr: false,
			validateActions: func(clientset *fake.Clientset) error {
				if len(clientset.Actions()) > 0 {
					return fmt.Errorf("expected 0 actions, got: \n%v", clientset.Actions())
				}
				return nil
			},
		},
		{
			name: "no-evict-one-deleted",
			fields: fields{
				operatorClient: nil,
				namespace:      "test-ns",
				pods: []*corev1.Pod{
					createPod(
						newPod("test-ns", "first", twoHoursAgo),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneHourAgo.Add(time.Minute)),
					),
					createPod(
						newPod("test-ns", "second", oneHourAgo),
						setDeleted(oneHourAgo.Add(10*time.Minute)),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneHourAgo.Add(time.Minute)),
					),
				},
				podSelector:     labels.Set{"label-1": "match"}.AsSelector(),
				minReadySeconds: 10,
				recorder:        events.NewInMemoryRecorder("testing"),
			},
			args:    args{},
			wantErr: false,
			validateActions: func(clientset *fake.Clientset) error {
				if len(clientset.Actions()) > 0 {
					return fmt.Errorf("expected 0 actions, got: \n%v", clientset.Actions())
				}
				return nil
			},
		},
		{
			name: "no-evict-one-ready-but-not-available",
			fields: fields{
				operatorClient: nil,
				namespace:      "test-ns",
				pods: []*corev1.Pod{
					createPod(
						newPod("test-ns", "first", twoHoursAgo),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneHourAgo.Add(time.Minute)),
					),
					createPod(
						newPod("test-ns", "second", oneHourAgo),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneSecondAgo),
					),
				},
				podSelector:     labels.Set{"label-1": "match"}.AsSelector(),
				minReadySeconds: 10,
				recorder:        events.NewInMemoryRecorder("testing"),
			},
			args:    args{},
			wantErr: false,
			validateActions: func(clientset *fake.Clientset) error {
				if len(clientset.Actions()) > 0 {
					return fmt.Errorf("expected 0 actions, got: \n%v", clientset.Actions())
				}
				return nil
			},
		},
		{
			name: "evict-two-pods-same-node",
			fields: fields{
				operatorClient: nil,
				namespace:      "test-ns",
				pods: []*corev1.Pod{
					createPod(
						newPod("test-ns", "first", twoHoursAgo),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneHourAgo.Add(time.Minute)),
					),
					createPod(
						newPod("test-ns", "second", oneHourAgo),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneMinuteAgo),
					),
				},
				podSelector:     labels.Set{"label-1": "match"}.AsSelector(),
				minReadySeconds: 10,
				recorder:        events.NewInMemoryRecorder("testing"),
			},
			args:    args{},
			wantErr: false,
			validateActions: func(clientset *fake.Clientset) error {
				actions := clientset.Actions()
				if len(actions) != 1 {
					return fmt.Errorf("expected 1 actions, got: \n%v", actions)
				}
				if !actions[0].Matches("create", "pods/eviction") {
					return fmt.Errorf("expected eviction, got %v", actions[0])
				}
				if actions[0].(kubetesting.CreateAction).GetObject().(*policyv1.Eviction).Name != "first" {
					return fmt.Errorf("expected eviction of first, got %v", actions[0])
				}
				return nil
			},
		}, {
			name: "evict-oldestthree-pods-same-node",
			fields: fields{
				operatorClient: nil,
				namespace:      "test-ns",
				pods: []*corev1.Pod{
					createPod(
						newPod("test-ns", "first", twoHoursAgo),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneHourAgo.Add(time.Minute)),
					),
					createPod(
						newPod("test-ns", "second", oneHourAgo),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneMinuteAgo),
					),
					createPod(
						newPod("test-ns", "third", oneHourAgo.Add(30*time.Minute)),
						setLabel("label-1", "match"),
						setNode("node-1"),
						makeReadyAt(oneHourAgo.Add(time.Minute)),
					),
				},
				podSelector:     labels.Set{"label-1": "match"}.AsSelector(),
				minReadySeconds: 10,
				recorder:        events.NewInMemoryRecorder("testing"),
			},
			args:    args{},
			wantErr: false,
			validateActions: func(clientset *fake.Clientset) error {
				actions := clientset.Actions()
				if len(actions) != 1 {
					return fmt.Errorf("expected 1 actions, got: \n%v", actions)
				}
				if !actions[0].Matches("create", "pods/eviction") {
					return fmt.Errorf("expected eviction, got %v", actions[0])
				}
				if actions[0].(kubetesting.CreateAction).GetObject().(*policyv1.Eviction).Name != "first" {
					return fmt.Errorf("expected eviction of first, got %v", actions[0])
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existingPods := []runtime.Object{}
			podIndex := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
			for i := range tt.fields.pods {
				podIndex.Add(tt.fields.pods[i])
				existingPods = append(existingPods, tt.fields.pods[i])
			}
			podLister := corev1listers.NewPodLister(podIndex)

			fakeClient := fake.NewSimpleClientset(existingPods...)

			c := &OnePodPerNodeController{
				name:            tt.fields.name,
				operatorClient:  tt.fields.operatorClient,
				minReadySeconds: tt.fields.minReadySeconds,
				clock:           fakeClock,
				namespace:       tt.fields.namespace,
				kubeClient:      fakeClient,
				podLister:       podLister,
				podSelector:     tt.fields.podSelector,
				recorder:        tt.fields.recorder,
			}
			if err := c.syncManaged(tt.args.ctx, tt.args.syncContext); (err != nil) != tt.wantErr {
				t.Errorf("syncManaged() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := tt.validateActions(fakeClient); err != nil {
				t.Error(err)
			}
		})
	}
}
