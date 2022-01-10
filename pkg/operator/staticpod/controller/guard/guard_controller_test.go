package guard

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
)

type FakeInfrastructureLister struct {
	InfrastructureLister_ configlistersv1.InfrastructureLister
}

func (l FakeInfrastructureLister) Get(name string) (*configv1.Infrastructure, error) {
	return l.InfrastructureLister_.Get(name)
}

func (l FakeInfrastructureLister) List(selector labels.Selector) (ret []*configv1.Infrastructure, err error) {
	return l.InfrastructureLister_.List(selector)
}

func TestIsSNOCheckFnc(t *testing.T) {
	tests := []struct {
		name        string
		infraObject *configv1.Infrastructure
		result      bool
		err         bool
	}{
		{
			name: "Missing Infrastructure status",
			infraObject: &configv1.Infrastructure{
				ObjectMeta: v1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.InfrastructureStatus{},
			},
			result: false,
			err:    true,
		},
		{
			name: "Missing ControlPlaneTopology",
			infraObject: &configv1.Infrastructure{
				ObjectMeta: v1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: "",
				},
			},
			result: false,
			err:    true,
		},
		{
			name: "ControlPlaneTopology not SingleReplicaTopologyMode",
			infraObject: &configv1.Infrastructure{
				ObjectMeta: v1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.HighlyAvailableTopologyMode,
				},
			},
			result: false,
		},
		{
			name: "ControlPlaneTopology is SingleReplicaTopologyMode",
			infraObject: &configv1.Infrastructure{
				ObjectMeta: v1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.SingleReplicaTopologyMode,
				},
			},
			result: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := indexer.Add(test.infraObject); err != nil {
				t.Fatal(err.Error())
			}
			lister := FakeInfrastructureLister{
				InfrastructureLister_: configlistersv1.NewInfrastructureLister(indexer),
			}

			conditionalFunction := IsSNOCheckFnc(lister)
			result, err := conditionalFunction()
			if test.err {
				if err == nil {
					t.Errorf("%s: expected error, got none", test.name)
				}
			} else {
				if err != nil {
					t.Errorf("%s: unexpected error: %v", test.name, err)
				} else if result != test.result {
					t.Errorf("%s: expected %v, got %v", test.name, test.result, result)
				}
			}
		})
	}
}

func fakeMasterNode(name string) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"node-role.kubernetes.io/master": "",
			},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}

	return n
}

type FakeSyncContext struct {
	recorder events.Recorder
}

func (f FakeSyncContext) Queue() workqueue.RateLimitingInterface {
	return nil
}

func (f FakeSyncContext) QueueKey() string {
	return ""
}

func (f FakeSyncContext) Recorder() events.Recorder {
	return f.recorder
}

// render a guarding pod
func TestRenderGuardPod(t *testing.T) {
	tests := []struct {
		name        string
		infraObject *configv1.Infrastructure
		errString   string
		err         bool
		operandPod  *corev1.Pod
		guardExists bool
		guardPod    *corev1.Pod
	}{
		{
			name: "Operand pod missing",
			infraObject: &configv1.Infrastructure{
				ObjectMeta: v1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.SingleReplicaTopologyMode,
				},
			},
			errString:  "Missing operand on node master1",
			err:        true,
			operandPod: nil,
		},
		{
			name: "Operand pod missing .Status.PodIP",
			infraObject: &configv1.Infrastructure{
				ObjectMeta: v1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.SingleReplicaTopologyMode,
				},
			},
			errString: "Missing PodIP in operand operand1 on node master1",
			err:       true,
			operandPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "operand1",
					Namespace: "test",
					Labels:    map[string]string{"app": "operand"},
				},
				Spec: corev1.PodSpec{
					NodeName: "master1",
				},
				Status: corev1.PodStatus{},
			},
		},
		{
			name: "Operand guard pod created",
			infraObject: &configv1.Infrastructure{
				ObjectMeta: v1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.SingleReplicaTopologyMode,
				},
			},
			operandPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "operand1",
					Namespace: "test",
					Labels:    map[string]string{"app": "operand"},
				},
				Spec: corev1.PodSpec{
					NodeName: "master1",
				},
				Status: corev1.PodStatus{
					PodIP: "1.1.1.1",
				},
			},
			guardExists: true,
		},
		{
			name: "Operand guard pod deleted",
			infraObject: &configv1.Infrastructure{
				ObjectMeta: v1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.HighlyAvailableTopologyMode,
				},
			},
			operandPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "operand1",
					Namespace: "test",
					Labels:    map[string]string{"app": "operand"},
				},
				Spec: corev1.PodSpec{
					NodeName: "master1",
				},
				Status: corev1.PodStatus{
					PodIP: "1.1.1.1",
				},
			},
			guardPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      getGuardPodName("operand", "master1"),
					Namespace: "test",
					Labels:    map[string]string{"app": "guard"},
				},
				Spec: corev1.PodSpec{
					NodeName: "master1",
				},
				Status: corev1.PodStatus{
					PodIP: "1.1.1.1",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := indexer.Add(test.infraObject); err != nil {
				t.Fatal(err.Error())
			}
			lister := FakeInfrastructureLister{
				InfrastructureLister_: configlistersv1.NewInfrastructureLister(indexer),
			}

			kubeClient := fake.NewSimpleClientset(fakeMasterNode("master1"))
			if test.operandPod != nil {
				kubeClient.Tracker().Add(test.operandPod)
			}
			if test.guardPod != nil {
				kubeClient.Tracker().Add(test.guardPod)
			}
			kubeInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute)
			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &corev1.ObjectReference{})

			ctrl := &GuardController{
				targetNamespace:         "test",
				podResourcePrefix:       "operand",
				operatorName:            "operator",
				operandPodLabelSelector: labels.Set{"app": "operand"}.AsSelector(),
				readyzPort:              "99999",
				nodeLister:              kubeInformers.Core().V1().Nodes().Lister(),
				podLister:               kubeInformers.Core().V1().Pods().Lister(),
				podGetter:               kubeClient.CoreV1(),
				pdbGetter:               kubeClient.PolicyV1(),
				pdbLister:               kubeInformers.Policy().V1().PodDisruptionBudgets().Lister(),
				installerPodImageFn:     getInstallerPodImageFromEnv,
				createConditionalFunc:   IsSNOCheckFnc(lister),
			}

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			kubeInformers.Start(ctx.Done())
			kubeInformers.WaitForCacheSync(ctx.Done())

			err := ctrl.sync(ctx, FakeSyncContext{recorder: eventRecorder})
			if test.err {
				if test.errString != err.Error() {
					t.Errorf("%s: expected error message %q, got %q", test.name, test.errString, err)
				}
			} else {
				if test.guardExists {
					p, err := kubeClient.CoreV1().Pods("test").Get(ctx, getGuardPodName("operand", "master1"), metav1.GetOptions{})
					if err != nil {
						t.Errorf("%s: unexpected error: %v", test.name, err)
					} else {
						probe := p.Spec.Containers[0].ReadinessProbe.HTTPGet
						if probe == nil {
							t.Errorf("%s: missing ReadinessProbe in the guard", test.name)
						}
						if probe.Host != test.operandPod.Status.PodIP {
							t.Errorf("%s: expected %q host in ReadinessProbe in the guard, got %q instead", test.name, test.operandPod.Status.PodIP, probe.Host)
						}

						if probe.Port.IntValue() != 99999 {
							t.Errorf("%s: unexpected port in ReadinessProbe in the guard, expected 99999, got %v instead", test.name, probe.Port.IntValue())
						}
					}
				} else {
					_, err := kubeClient.CoreV1().Pods("test").Get(ctx, getGuardPodName("operand", "master1"), metav1.GetOptions{})
					if !apierrors.IsNotFound(err) {
						t.Errorf("%s: expected 'pods \"%v\" not found' error, got %q instead", test.name, getGuardPodName("operand", "master1"), err)
					}
				}
			}
		})
	}
}

// change a guard pod based on a change of an operand ip address (to update the readiness probe)
func TestRenderGuardPodPortChanged(t *testing.T) {
	infraObject := &configv1.Infrastructure{
		ObjectMeta: v1.ObjectMeta{
			Name: "cluster",
		},
		Status: configv1.InfrastructureStatus{
			ControlPlaneTopology: configv1.SingleReplicaTopologyMode,
		},
	}
	operandPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "operand1",
			Namespace: "test",
			Labels:    map[string]string{"app": "operand"},
		},
		Spec: corev1.PodSpec{
			NodeName: "master1",
		},
		Status: corev1.PodStatus{
			PodIP: "2.2.2.2",
		},
	}
	guardPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getGuardPodName("operand", "master1"),
			Namespace: "test",
			Labels:    map[string]string{"app": "guard"},
		},
		Spec: corev1.PodSpec{
			NodeName: "master1",
			Containers: []corev1.Container{
				{
					Image: "",
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Host: "1.1.1.1",
								Port: intstr.FromInt(99999),
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			PodIP: "1.1.1.1",
		},
	}

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if err := indexer.Add(infraObject); err != nil {
		t.Fatal(err.Error())
	}
	lister := FakeInfrastructureLister{
		InfrastructureLister_: configlistersv1.NewInfrastructureLister(indexer),
	}

	kubeClient := fake.NewSimpleClientset(fakeMasterNode("master1"), operandPod, guardPod)
	kubeInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute)
	eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &corev1.ObjectReference{})

	ctrl := &GuardController{
		targetNamespace:         "test",
		podResourcePrefix:       "operand",
		operandPodLabelSelector: labels.Set{"app": "operand"}.AsSelector(),
		operatorName:            "operator",
		readyzPort:              "99999",
		nodeLister:              kubeInformers.Core().V1().Nodes().Lister(),
		podLister:               kubeInformers.Core().V1().Pods().Lister(),
		podGetter:               kubeClient.CoreV1(),
		pdbGetter:               kubeClient.PolicyV1(),
		pdbLister:               kubeInformers.Policy().V1().PodDisruptionBudgets().Lister(),
		installerPodImageFn:     getInstallerPodImageFromEnv,
		createConditionalFunc:   IsSNOCheckFnc(lister),
	}

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	kubeInformers.Start(ctx.Done())
	kubeInformers.WaitForCacheSync(ctx.Done())

	// expected to pass
	if err := ctrl.sync(ctx, FakeSyncContext{recorder: eventRecorder}); err != nil {
		t.Fatal(err.Error())
	}

	// check the probe.Host is the same as the operand ip address
	p, err := kubeClient.CoreV1().Pods("test").Get(ctx, getGuardPodName("operand", "master1"), metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	} else {
		probe := p.Spec.Containers[0].ReadinessProbe.HTTPGet
		if probe == nil {
			t.Errorf("missing ReadinessProbe in the guard")
		}
		if probe.Host != operandPod.Status.PodIP {
			t.Errorf("expected %q host in ReadinessProbe in the guard, got %q instead", operandPod.Status.PodIP, probe.Host)
		}

		if probe.Port.IntValue() != 99999 {
			t.Errorf("unexpected port in ReadinessProbe in the guard, expected 99999, got %v instead", probe.Port.IntValue())
		}
	}
}
