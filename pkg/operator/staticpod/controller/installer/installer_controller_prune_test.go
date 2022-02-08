package installer

import (
	"context"
	"fmt"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/staticpod/controller/revision"
	"k8s.io/client-go/informers"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestPrune(t *testing.T) {
	tests := []struct {
		name string

		failedLimit    int32
		succeededLimit int32

		targetNamespace string
		status          operatorv1.StaticPodOperatorStatus

		objects                   []int32
		expectedObjects           []int32
		expectedObjectsOnNextSync []int32 // recheck after first sync reevaluates TargetRevision

		expectedInstallPod  bool
		expectedInstallArgs string
	}{
		{
			name:            "prunes api resources based on failedLimit 1, succeedLimit 1",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 4,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:        "test-node-1",
						CurrentRevision: 2,
						TargetRevision:  4,
					},
				},
			},
			failedLimit:         1,
			succeededLimit:      1,
			objects:             []int32{1, 2, 3, 4},
			expectedObjects:     []int32{2, 4},
			expectedInstallPod:  true,
			expectedInstallArgs: "-v=4 --revision=4 --namespace=prune-api --pod=test-pod --resource-dir=/etc/kubernetes/static-pod-resources --pod-manifest-dir=/etc/kubernetes/manifests --max-eligible-revision-to-prune=4 --protected-revisions-from-pruning=2,4 --configmaps=test-pod --secrets=test-secret",
		},
		{
			name:            "prunes api resources with multiple nodes based on failedLimit 1, succeedLimit 1",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 5,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:        "test-node-1",
						CurrentRevision: 2,
						TargetRevision:  5,
					},
					{
						NodeName:        "test-node-2",
						CurrentRevision: 3,
						TargetRevision:  5,
					},
					{
						NodeName:        "test-node-3",
						CurrentRevision: 4,
						TargetRevision:  5,
					},
				},
			},
			failedLimit:         1,
			succeededLimit:      1,
			objects:             []int32{1, 2, 3, 4, 5, 6},
			expectedObjects:     []int32{2, 3, 4, 5, 6},
			expectedInstallPod:  true,
			expectedInstallArgs: "-v=4 --revision=5 --namespace=prune-api --pod=test-pod --resource-dir=/etc/kubernetes/static-pod-resources --pod-manifest-dir=/etc/kubernetes/manifests --max-eligible-revision-to-prune=5 --protected-revisions-from-pruning=2,3,4,5 --configmaps=test-pod --secrets=test-secret",
		},
		{
			name:            "prunes api resources without nodes",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 1,
				NodeStatuses:            []operatorv1.NodeStatus{},
			},
			failedLimit:        1,
			succeededLimit:     1,
			objects:            []int32{1, 2, 3, 4, 5, 6},
			expectedObjects:    []int32{1, 2, 3, 4, 5, 6},
			expectedInstallPod: false,
		},
		{
			name:            "prunes api resources based on failedLimit 2, succeedLimit 3",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 10,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:        "test-node-1",
						CurrentRevision: 4,
						TargetRevision:  7,
					},
				},
			},
			failedLimit:               2,
			succeededLimit:            3,
			objects:                   []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			expectedObjects:           []int32{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			expectedObjectsOnNextSync: []int32{2, 3, 4, 8, 9, 10, 11, 12},
			expectedInstallPod:        true,
			expectedInstallArgs:       "-v=4 --revision=10 --namespace=prune-api --pod=test-pod --resource-dir=/etc/kubernetes/static-pod-resources --pod-manifest-dir=/etc/kubernetes/manifests --max-eligible-revision-to-prune=10 --protected-revisions-from-pruning=2,3,4,8,9,10 --configmaps=test-pod --secrets=test-secret",
		},
		{
			name:            "prunes api resources based on failedLimit 2, succeedLimit 3 and all relevant revisions set",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 40,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:           "test-node-1",
						CurrentRevision:    10,
						TargetRevision:     30,
						LastFailedRevision: 20,
					},
				},
			},
			failedLimit:               2,
			succeededLimit:            3,
			objects:                   int32Range(1, 50),
			expectedObjects:           []int32{8, 9, 10, 19, 20, 28, 29, 30, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50},
			expectedObjectsOnNextSync: []int32{8, 9, 10, 19, 20, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50},
			expectedInstallPod:        true,
			expectedInstallArgs:       "-v=4 --revision=40 --namespace=prune-api --pod=test-pod --resource-dir=/etc/kubernetes/static-pod-resources --pod-manifest-dir=/etc/kubernetes/manifests --max-eligible-revision-to-prune=40 --protected-revisions-from-pruning=8,9,10,19,20,38,39,40 --configmaps=test-pod --secrets=test-secret",
		},
		{
			name:            "prunes api resources based on failedLimit 0, succeedLimit 0",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 40,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:           "test-node-1",
						CurrentRevision:    10,
						TargetRevision:     30,
						LastFailedRevision: 20,
					},
				},
			},
			failedLimit:               0,
			succeededLimit:            0,
			objects:                   int32Range(1, 50),
			expectedObjects:           []int32{6, 7, 8, 9, 10, 16, 17, 18, 19, 20, 26, 27, 28, 29, 30, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50},
			expectedObjectsOnNextSync: []int32{6, 7, 8, 9, 10, 16, 17, 18, 19, 20, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50},
			expectedInstallPod:        true,
			expectedInstallArgs:       "-v=4 --revision=40 --namespace=prune-api --pod=test-pod --resource-dir=/etc/kubernetes/static-pod-resources --pod-manifest-dir=/etc/kubernetes/manifests --max-eligible-revision-to-prune=40 --protected-revisions-from-pruning=6,7,8,9,10,16,17,18,19,20,36,37,38,39,40 --configmaps=test-pod --secrets=test-secret",
		},
		{
			name:            "protects all",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 20,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:           "test-node-1",
						CurrentRevision:    10,
						TargetRevision:     15,
						LastFailedRevision: 5,
					},
				},
			},
			failedLimit:        5,
			succeededLimit:     5,
			objects:            []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			expectedObjects:    []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			expectedInstallPod: false,
		},
		{
			name:            "protects all with different nodes",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 20,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:        "test-node-1",
						CurrentRevision: 15,
					},
					{
						NodeName:           "test-node-2",
						CurrentRevision:    10,
						LastFailedRevision: 5,
					},
				},
			},
			failedLimit:        5,
			succeededLimit:     5,
			objects:            []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			expectedObjects:    []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			expectedInstallPod: false,
		},
		{
			name:            "protects all with unlimited revisions",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 1,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:        "test-node-1",
						CurrentRevision: 1,
						TargetRevision:  0,
					},
				},
			},
			failedLimit:        -1,
			succeededLimit:     -1,
			objects:            []int32{1, 2, 3},
			expectedObjects:    []int32{1, 2, 3},
			expectedInstallPod: false,
		},
		{
			name:            "protects all with unlimited succeeded revisions",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 5,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:        "test-node-1",
						CurrentRevision: 1,
						TargetRevision:  0,
					},
				},
			},
			failedLimit:               1,
			succeededLimit:            -1,
			objects:                   []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedObjects:           []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedObjectsOnNextSync: []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedInstallPod:        true,
			expectedInstallArgs:       "-v=4 --revision=5 --namespace=prune-api --pod=test-pod --resource-dir=/etc/kubernetes/static-pod-resources --pod-manifest-dir=/etc/kubernetes/manifests --max-eligible-revision-to-prune=-1 --protected-revisions-from-pruning= --configmaps=test-pod --secrets=test-secret",
		},
		{
			name:            "protects all with unlimited failed revisions",
			targetNamespace: "prune-api",
			status: operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: 5,
				NodeStatuses: []operatorv1.NodeStatus{
					{
						NodeName:        "test-node-1",
						CurrentRevision: 1,
						TargetRevision:  0,
					},
				},
			},
			failedLimit:               -1,
			succeededLimit:            1,
			objects:                   []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedObjects:           []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedObjectsOnNextSync: []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectedInstallPod:        true,
			expectedInstallArgs:       "-v=4 --revision=5 --namespace=prune-api --pod=test-pod --resource-dir=/etc/kubernetes/static-pod-resources --pod-manifest-dir=/etc/kubernetes/manifests --max-eligible-revision-to-prune=-1 --protected-revisions-from-pruning= --configmaps=test-pod --secrets=test-secret",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset(
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: tc.targetNamespace, Name: fmt.Sprintf("%s-%d", "test-secret", tc.status.LatestAvailableRevision)}},
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: tc.targetNamespace, Name: fmt.Sprintf("%s-%d", "test-pod", tc.status.LatestAvailableRevision)}},
			)
			kubeInformers := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace(tc.targetNamespace))
			for _, rev := range tc.objects {
				_ = kubeClient.Tracker().Add(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("revision-status-%d", rev), Namespace: tc.targetNamespace},
					Data: map[string]string{
						"revision": fmt.Sprintf("%d", rev),
					},
				})
			}
			fakeStaticPodOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					FailedRevisionLimit:    tc.failedLimit,
					SucceededRevisionLimit: tc.succeededLimit,
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
						LogLevel:        operatorv1.Debug,
					},
				},
				&tc.status,
				nil,
				nil,
			)
			var installPod *corev1.Pod
			kubeClient.PrependReactor("create", "pods", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
				fmt.Println(action)
				installPod = action.(ktesting.CreateAction).GetObject().(*corev1.Pod)
				return false, nil, nil
			})
			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events(tc.targetNamespace), "test-operator", &corev1.ObjectReference{})

			c := NewInstallerController(
				tc.targetNamespace, "test-pod",
				[]revision.RevisionResource{{Name: "test-pod"}},
				[]revision.RevisionResource{{Name: "test-secret"}},
				[]string{"/bin/true", "--foo=test", "--bar"},
				kubeInformers,
				fakeStaticPodOperatorClient,
				kubeClient.CoreV1(),
				kubeClient.CoreV1(),
				kubeClient.CoreV1(),
				eventRecorder,
			)

			for _, expectedObjects := range [][]int32{tc.expectedObjects, tc.expectedObjectsOnNextSync} {
				if expectedObjects == nil {
					continue
				}
				err := c.Sync(context.TODO(), factory.NewSyncContext("InstallerController", eventRecorder))
				if err != nil {
					t.Fatal(err)
				}

				// check configmap still existing
				statusConfigMaps, err := c.configMapsGetter.ConfigMaps(tc.targetNamespace).List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatalf("unexpected error %q", err)
				}
				expected := sets.NewInt32(expectedObjects...)
				got := sets.NewInt32(configMapRevisions(t, statusConfigMaps.Items)...)
				if missing := expected.Difference(got); len(missing) > 0 {
					t.Errorf("got %+v, missing %+v", got.List(), missing.List())
				}
				if unexpected := got.Difference(expected); len(unexpected) > 0 {
					t.Errorf("got %+v, unexpected %+v", got.List(), unexpected.List())
				}
			}

			// check prune pod
			if !tc.expectedInstallPod && installPod != nil {
				t.Errorf("unexpected installer pod created with command: %v", installPod.Spec.Containers[0].Args)
			} else if tc.expectedInstallPod && installPod == nil {
				t.Error("expected installer pod, but it has not been created")
			} else if tc.expectedInstallPod {
				gotArgs := strings.Join(installPod.Spec.Containers[0].Args, " ")
				if gotArgs != tc.expectedInstallArgs {
					t.Errorf("unexpected arguments:\n      got: %s\n expected: %s", gotArgs, tc.expectedInstallArgs)
				}
			}
		})
	}
}

func int32Range(from, to int32) []int32 {
	ret := make([]int32, to-from+1)
	for i := from; i <= to; i++ {
		ret[i-from] = i
	}
	return ret
}

func configMapRevisions(t *testing.T, objs []corev1.ConfigMap) []int32 {
	revs := make([]int32, 0, len(objs))
	for _, o := range objs {
		if !strings.HasPrefix(o.Name, "revision-status") {
			continue
		}
		if rev, err := strconv.Atoi(o.Data["revision"]); err != nil {
			t.Fatal(err)
		} else {
			revs = append(revs, int32(rev))
		}
	}
	return revs
}
