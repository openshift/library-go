package guard

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
)

func TestRetiredNodesGuardPolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		filter      NodeFilterFunc
		wantMinimum int
		wantGuard   bool
		wantError   bool
	}{
		{name: "default consumer keeps existing policy", wantMinimum: 3, wantGuard: true},
		{name: "explicit retired Node is excluded", filter: omitFirstGuardNode, wantMinimum: 2},
		{name: "failed filter restores conservative policy", filter: func(context.Context, []*corev1.Node) ([]*corev1.Node, error) {
			return nil, errors.New("membership unavailable")
		}, wantMinimum: 3, wantGuard: true, wantError: true},
		{name: "empty result is rejected", filter: func(context.Context, []*corev1.Node) ([]*corev1.Node, error) { return nil, nil }, wantMinimum: 3, wantGuard: true, wantError: true},
		{name: "foreign Node is rejected", filter: func(context.Context, []*corev1.Node) ([]*corev1.Node, error) {
			return []*corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "foreign"}}}, nil
		}, wantMinimum: 3, wantGuard: true, wantError: true},
		{name: "duplicate Node is rejected", filter: func(_ context.Context, nodes []*corev1.Node) ([]*corev1.Node, error) {
			return []*corev1.Node{nodes[0], nodes[0]}, nil
		}, wantMinimum: 3, wantGuard: true, wantError: true},
		{name: "nil Node is rejected", filter: func(context.Context, []*corev1.Node) ([]*corev1.Node, error) { return []*corev1.Node{nil}, nil }, wantMinimum: 3, wantGuard: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
			ctrl.nodeFilter = tc.filter
			// Start from a previously reduced budget. A failed filter must
			// actively restore protection, not merely skip this sync.
			pdb, err := kube.PolicyV1().PodDisruptionBudgets("test").Get(context.Background(), "operand-guard-pdb", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pdb.Spec.MinAvailable = ptrMinimum(2)
			if _, err := kube.PolicyV1().PodDisruptionBudgets("test").Update(context.Background(), pdb, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			refresh()
			err = ctrl.sync(context.Background(), syncContext)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError = %t", err, tc.wantError)
			}
			actual, err := kube.PolicyV1().PodDisruptionBudgets("test").Get(context.Background(), "operand-guard-pdb", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if actual.Spec.MinAvailable.IntValue() != tc.wantMinimum {
				t.Fatalf("minAvailable = %v, want %d", actual.Spec.MinAvailable, tc.wantMinimum)
			}
			_, err = kube.CoreV1().Pods("test").Get(context.Background(), "operand-guard-master-0", metav1.GetOptions{})
			if (err == nil) != tc.wantGuard || (err != nil && !apierrors.IsNotFound(err)) {
				t.Fatalf("retired guard Get error = %v, wantGuard = %t", err, tc.wantGuard)
			}
		})
	}
}

func TestRetiredGuardDisappearsBeforeBudgetReduction(t *testing.T) {
	ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
	ctrl.nodeFilter = omitFirstGuardNode
	reduced := false
	kube.PrependReactor("update", "poddisruptionbudgets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		budget := action.(clienttesting.UpdateAction).GetObject().(*policyv1.PodDisruptionBudget)
		if budget.Spec.MinAvailable.IntValue() < 3 {
			_, err := kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("pods"), "test", "operand-guard-master-0")
			if !apierrors.IsNotFound(err) {
				t.Fatalf("budget reduced before the retiring guard disappeared: %v", err)
			}
			reduced = true
		}
		return false, nil, nil
	})
	kube.PrependReactor("patch", "poddisruptionbudgets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		t.Fatal("unexpected PDB patch; extend this test to inspect patch writes")
		return false, nil, nil
	})
	if err := ctrl.sync(context.Background(), syncContext); err != nil {
		t.Fatal(err)
	}
	if !reduced {
		t.Fatal("expected a budget reduction after guard deletion")
	}
	refresh()
	if err := ctrl.sync(context.Background(), syncContext); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().Pods("test").Get(context.Background(), "operand-guard-master-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("retired guard was recreated: %v", err)
	}
}

func TestRetiredGuardDeletionFailureKeepsBudget(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("deletionPending=%t", pending), func(t *testing.T) {
			ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
			ctrl.nodeFilter = omitFirstGuardNode
			pdb, err := kube.PolicyV1().PodDisruptionBudgets("test").Get(context.Background(), "operand-guard-pdb", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pdb.Spec.MinAvailable = ptrMinimum(2)
			if _, err := kube.PolicyV1().PodDisruptionBudgets("test").Update(context.Background(), pdb, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			// Update the controller's PDB cache too, as if the previous
			// reduced policy had already been fully observed.
			refresh()
			kube.PrependReactor("delete", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
				if action.(clienttesting.DeleteAction).GetName() != "operand-guard-master-0" {
					return false, nil, nil
				}
				if pending {
					return true, nil, nil
				} // API accepted deletion, object still exists.
				// The API can remove the guard even when the client sees an error.
				if err := kube.Tracker().Delete(action.GetResource(), action.GetNamespace(), "operand-guard-master-0"); err != nil {
					t.Fatal(err)
				}
				return true, nil, errors.New("deletion response lost")
			})
			if err := ctrl.sync(context.Background(), syncContext); err == nil {
				t.Fatal("expected guard cleanup to block budget reduction")
			}
			pdb, err = kube.PolicyV1().PodDisruptionBudgets("test").Get(context.Background(), "operand-guard-pdb", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if pdb.Spec.MinAvailable.IntValue() != 3 {
				t.Fatalf("budget was lowered before guard disappeared: %v", pdb.Spec.MinAvailable)
			}
			if !pending {
				_, err := kube.CoreV1().Pods("test").Get(context.Background(), "operand-guard-master-0", metav1.GetOptions{})
				if !apierrors.IsNotFound(err) {
					t.Fatalf("cleanup retry recreated the retired guard: %v", err)
				}
			}
		})
	}
}

func TestRetiredGuardUncertainIdentityRestoresBudget(t *testing.T) {
	for _, mode := range []string{"read unavailable", "different Node", "different label"} {
		t.Run(mode, func(t *testing.T) {
			ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
			ctrl.nodeFilter = omitFirstGuardNode
			ctx := context.Background()
			pdb, err := kube.PolicyV1().PodDisruptionBudgets("test").Get(ctx, "operand-guard-pdb", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pdb.Spec.MinAvailable = ptrMinimum(2)
			if _, err := kube.PolicyV1().PodDisruptionBudgets("test").Update(ctx, pdb, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			pod, err := kube.CoreV1().Pods("test").Get(ctx, "operand-guard-master-0", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "read unavailable":
				kube.PrependReactor("get", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
					if action.(clienttesting.GetAction).GetName() == pod.Name {
						return true, nil, errors.New("guard read unavailable")
					}
					return false, nil, nil
				})
			case "different Node":
				pod.Spec.NodeName = "another-node"
			case "different label":
				pod.Labels["app"] = "unrelated"
			}
			if mode != "read unavailable" {
				if _, err := kube.CoreV1().Pods("test").Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			refresh()
			kube.ClearActions()
			if err := ctrl.sync(ctx, syncContext); err == nil {
				t.Fatal("uncertain guard identity must report an error")
			}
			pdb, err = kube.PolicyV1().PodDisruptionBudgets("test").Get(ctx, "operand-guard-pdb", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if pdb.Spec.MinAvailable.IntValue() != 3 {
				t.Fatalf("uncertainty retained a reduced budget: %v", pdb.Spec.MinAvailable)
			}
			for _, action := range kube.Actions() {
				if action.Matches("delete", "pods") && action.(clienttesting.DeleteAction).GetName() == pod.Name {
					t.Fatal("guard with unverified identity was deleted")
				}
			}
		})
	}
}

func TestRetiredGuardUIDPrecondition(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprintf("conflict=%t", conflict), func(t *testing.T) {
			ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
			ctrl.nodeFilter = omitFirstGuardNode
			ctx := context.Background()
			pod, err := kube.CoreV1().Pods("test").Get(ctx, "operand-guard-master-0", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pod.UID = types.UID("original-guard")
			pod.ResourceVersion = "observed-version"
			if _, err := kube.CoreV1().Pods("test").Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			refresh()
			checkedUID := false
			kube.PrependReactor("delete", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
				deletion := action.(clienttesting.DeleteAction)
				if deletion.GetName() != pod.Name {
					return false, nil, nil
				}
				preconditions := deletion.GetDeleteOptions().Preconditions
				if preconditions == nil || preconditions.UID == nil || *preconditions.UID != pod.UID {
					t.Fatal("retirement deletion must target the UID that was read")
				}
				if preconditions.ResourceVersion == nil || *preconditions.ResourceVersion != pod.ResourceVersion {
					t.Fatal("retirement deletion must preserve the observed Pod resource version")
				}
				checkedUID = true
				if conflict {
					return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, pod.Name, errors.New("UID changed"))
				}
				return false, nil, nil
			})
			err = ctrl.sync(ctx, syncContext)
			if (err != nil) != conflict || !checkedUID {
				t.Fatalf("error=%v checkedUID=%t, expected conflict=%t", err, checkedUID, conflict)
			}
			pdb, err := kube.PolicyV1().PodDisruptionBudgets("test").Get(ctx, "operand-guard-pdb", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			wantMinimum := 2
			if conflict {
				wantMinimum = 3
			}
			if pdb.Spec.MinAvailable.IntValue() != wantMinimum {
				t.Fatalf("minAvailable=%v, want %d", pdb.Spec.MinAvailable, wantMinimum)
			}
		})
	}
}

func TestRetirementWaitsForConservativeBudgetObservation(t *testing.T) {
	ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
	ctrl.nodeFilter = omitFirstGuardNode
	ctx := context.Background()
	pdb, err := kube.PolicyV1().PodDisruptionBudgets("test").Get(ctx, "operand-guard-pdb", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Explicit status inputs test the generation barrier only; a real
	// disruption controller and admission are not running in this unit test.
	pdb.Generation = 2
	pdb.Status.ObservedGeneration = 1
	if _, err := kube.PolicyV1().PodDisruptionBudgets("test").Update(ctx, pdb, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	refresh()
	if err := ctrl.sync(ctx, syncContext); err == nil {
		t.Fatal("expected retirement to wait for conservative budget observation")
	}
	if _, err := kube.CoreV1().Pods("test").Get(ctx, "operand-guard-master-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("guard disappeared before the observation barrier: %v", err)
	}
	pdb, err = kube.PolicyV1().PodDisruptionBudgets("test").Get(ctx, pdb.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pdb.Status.ObservedGeneration = pdb.Generation
	if _, err := kube.PolicyV1().PodDisruptionBudgets("test").UpdateStatus(ctx, pdb, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	refresh()
	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().Pods("test").Get(ctx, "operand-guard-master-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("verified guard did not retire after observation: %v", err)
	}
}

func TestRetirementPreservesRetainedHealthFloor(t *testing.T) {
	for _, mode := range []string{"exactly two healthy", "two unhealthy", "two terminating", "two approved disruptions"} {
		t.Run(mode, func(t *testing.T) {
			ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
			ctrl.nodeFilter = omitFirstGuardNode
			ctx := context.Background()
			count := 2
			if mode == "exactly two healthy" {
				count = 1
			}
			pdb, err := kube.PolicyV1().PodDisruptionBudgets("test").Get(ctx, "operand-guard-pdb", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= count; i++ {
				name := fmt.Sprintf("operand-guard-master-%d", i)
				pod, err := kube.CoreV1().Pods("test").Get(ctx, name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "two terminating":
					now := metav1.Now()
					pod.DeletionTimestamp = &now
					pod.Finalizers = []string{"test"}
				case "two approved disruptions":
					if pdb.Status.DisruptedPods == nil {
						pdb.Status.DisruptedPods = map[string]metav1.Time{}
					}
					pdb.Status.DisruptedPods[name] = metav1.Now()
				default:
					pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
				}
				if _, err := kube.CoreV1().Pods("test").Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := kube.PolicyV1().PodDisruptionBudgets("test").UpdateStatus(ctx, pdb, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			refresh()
			err = ctrl.sync(ctx, syncContext)
			blocked := mode != "exactly two healthy"
			if (err != nil) != blocked {
				t.Fatalf("error=%v, wantBlocked=%t", err, blocked)
			}
			_, getErr := kube.CoreV1().Pods("test").Get(ctx, "operand-guard-master-0", metav1.GetOptions{})
			if blocked && getErr != nil {
				t.Fatalf("healthy outgoing guard was removed below the retained health floor: %v", getErr)
			}
			if !blocked && !apierrors.IsNotFound(getErr) {
				t.Fatalf("retirement did not proceed at the health floor: %v", getErr)
			}
		})
	}
}

func omitFirstGuardNode(_ context.Context, nodes []*corev1.Node) ([]*corev1.Node, error) {
	var kept []*corev1.Node
	for _, node := range nodes {
		if node.Name != "master-0" {
			kept = append(kept, node)
		}
	}
	return kept, nil
}

func ptrMinimum(n int) *intstr.IntOrString {
	value := intstr.FromInt(n)
	return &value
}

func retiredGuardFixture(t *testing.T) (*GuardController, *fake.Clientset, func(), FakeSyncContext) {
	t.Helper()
	var objects []runtime.Object
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("master-%d", i)
		ip := fmt.Sprintf("192.0.2.%d", i+10)
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"node-role.kubernetes.io/master": ""}}}
		operand := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operand-" + name, Namespace: "test", Labels: map[string]string{"app": "operand"}}, Spec: corev1.PodSpec{NodeName: name}, Status: corev1.PodStatus{PodIP: ip}}
		pod := resourceread.ReadPodV1OrDie(podTemplate)
		pod.Name, pod.Namespace, pod.Spec.NodeName = getGuardPodName("operand", name), "test", name
		pod.Spec.ServiceAccountName = resourceread.ReadServiceAccountV1OrDie(serviceAccountTemplate).Name
		pod.Spec.Hostname = getGuardPodHostname("test", name)
		pod.Spec.Containers[0].Image = "example.invalid/operator:test"
		pod.Spec.Containers[0].ReadinessProbe.HTTPGet.Host = ip
		pod.Spec.Containers[0].ReadinessProbe.HTTPGet.Port = intstr.FromInt(9980)
		pod.Spec.Containers[0].ReadinessProbe.HTTPGet.Path = "readyz"
		// Even a stale Ready guard must disappear before reducing the budget.
		pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}
		objects = append(objects, node, operand, pod)
	}
	objects = append(objects, &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "operand-guard-pdb", Namespace: "test"}, Status: policyv1.PodDisruptionBudgetStatus{ExpectedPods: 3}, Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: ptrMinimum(3), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "guard"}}}})
	kube := fake.NewSimpleClientset(objects...)
	inf := informers.NewSharedInformerFactory(kube, 0)
	nodes, pods, pdbs := inf.Core().V1().Nodes(), inf.Core().V1().Pods(), inf.Policy().V1().PodDisruptionBudgets()
	refresh := func() {
		t.Helper()
		for _, store := range []cache.Store{nodes.Informer().GetStore(), pods.Informer().GetStore(), pdbs.Informer().GetStore()} {
			if err := store.Replace(nil, ""); err != nil {
				t.Fatal(err)
			}
		}
		nodeList, err := kube.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for i := range nodeList.Items {
			if err := nodes.Informer().GetStore().Add(&nodeList.Items[i]); err != nil {
				t.Fatal(err)
			}
		}
		podList, err := kube.CoreV1().Pods("test").List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for i := range podList.Items {
			if err := pods.Informer().GetStore().Add(&podList.Items[i]); err != nil {
				t.Fatal(err)
			}
		}
		pdbList, err := kube.PolicyV1().PodDisruptionBudgets("test").List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for i := range pdbList.Items {
			if err := pdbs.Informer().GetStore().Add(&pdbList.Items[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	refresh()
	ctrl := &GuardController{
		targetNamespace: "test", podResourcePrefix: "operand", operatorName: "operator", readyzPort: "9980", readyzEndpoint: "readyz",
		operandPodLabelSelector: labels.SelectorFromSet(labels.Set{"app": "operand"}), masterNodesSelector: masterNodesSelector(t),
		nodeLister: nodes.Lister(), podLister: pods.Lister(), pdbLister: pdbs.Lister(), podGetter: kube.CoreV1(), pdbGetter: kube.PolicyV1(),
		saLister: inf.Core().V1().ServiceAccounts().Lister(), saGetter: kube.CoreV1(),
		installerPodImageFn: func() string { return "example.invalid/operator:test" }, createConditionalFunc: func() (bool, bool, error) { return true, true, nil },
	}
	return ctrl, kube, refresh, FakeSyncContext{recorder: events.NewInMemoryRecorder("test", clock.RealClock{})}
}

func TestWaitForRetainedGuardAccounting(t *testing.T) {
	ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
	ctx := context.Background()
	budgets := kube.PolicyV1().PodDisruptionBudgets("test")
	const budgetName = "operand-guard-pdb"
	if err := kube.CoreV1().Pods("test").Delete(ctx, "operand-guard-master-0", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}

	for _, stage := range []struct {
		expectedPods int32
		wantMinimum  int
	}{
		{expectedPods: 4, wantMinimum: 3},
		{expectedPods: 3, wantMinimum: 2},
	} {
		pdb, err := budgets.Get(ctx, budgetName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pdb.Status.ExpectedPods = stage.expectedPods
		if _, err := budgets.UpdateStatus(ctx, pdb, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		refresh()
		// Start from the fixture controller configuration with no prior
		// retirement reconciliation. The API objects carry the transition.
		restarted := *ctrl
		restarted.nodeFilter = omitFirstGuardNode
		if err := restarted.sync(ctx, syncContext); (err != nil) != (stage.wantMinimum == 3) {
			t.Fatalf("expectedPods=%d: unexpected sync result: %v", stage.expectedPods, err)
		}
		pdb, err = budgets.Get(ctx, budgetName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got := pdb.Spec.MinAvailable.IntValue(); got != stage.wantMinimum {
			t.Fatalf("expectedPods=%d: minAvailable=%d, want %d", stage.expectedPods, got, stage.wantMinimum)
		}
		if _, err := kube.CoreV1().Pods("test").Get(ctx, "operand-guard-master-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("retired guard was recreated: %v", err)
		}
	}
}

func TestRetirementRepairsPDBSelectorBeforeReducingMinimum(t *testing.T) {
	ctrl, kube, _, syncContext := retiredGuardFixture(t)
	ctrl.nodeFilter = omitFirstGuardNode
	ctx := context.Background()
	if err := kube.CoreV1().Pods("test").Delete(ctx, "operand-guard-master-0", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	budgets := kube.PolicyV1().PodDisruptionBudgets("test")
	budget, err := budgets.Get(ctx, "operand-guard-pdb", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	budget.Spec.Selector.MatchLabels["app"] = "different"
	if _, err := budgets.Update(ctx, budget, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.sync(ctx, syncContext); err == nil {
		t.Fatal("expected reconciliation to wait for PDB accounting")
	}
	budget, err = budgets.Get(ctx, budget.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if budget.Spec.Selector.MatchLabels["app"] != "guard" || budget.Spec.MinAvailable.IntValue() != 3 {
		t.Fatalf("expected intended selector and conservative minimum, got %+v", budget.Spec)
	}
}

func TestRetirementDeduplicatesOverlappingSelectors(t *testing.T) {
	ctrl, kube, _, syncContext := retiredGuardFixture(t)
	ctrl.extraNodeSelector = ctrl.masterNodesSelector
	ctrl.nodeFilter = func(_ context.Context, nodes []*corev1.Node) ([]*corev1.Node, error) {
		if len(nodes) != 4 {
			t.Fatalf("expected four unique selected Nodes, got %d", len(nodes))
		}
		return nodes, nil
	}
	ctx := context.Background()
	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	budget, err := kube.PolicyV1().PodDisruptionBudgets("test").Get(ctx, "operand-guard-pdb", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if budget.Spec.MinAvailable.IntValue() != 3 {
		t.Fatalf("expected minimum of three, got %v", budget.Spec.MinAvailable)
	}
}

func TestRetirementKeepsReducedBudgetWhileStatusLags(t *testing.T) {
	ctrl, kube, _, syncContext := retiredGuardFixture(t)
	ctrl.nodeFilter = omitFirstGuardNode
	ctx := context.Background()
	budgets := kube.PolicyV1().PodDisruptionBudgets("test")
	const budgetName = "operand-guard-pdb"

	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	budget, err := budgets.Get(ctx, budgetName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if budget.Spec.MinAvailable.IntValue() != 2 {
		t.Fatal("expected an applied reduction before simulating status lag")
	}
	// Fake clients do not increment Generation on a spec write.
	budget.Generation = 2
	budget.Status.ObservedGeneration = 1
	if _, err := budgets.Update(ctx, budget, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatalf("reconcile while PDB status lags: %v", err)
	}
	budget, err = budgets.Get(ctx, budgetName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := budget.Spec.MinAvailable.IntValue(); got != 2 {
		t.Fatalf("status lag undid the budget reduction: minAvailable=%d", got)
	}
}

func TestRetirementBudgetReductionConflictsWithEvictionReservation(t *testing.T) {
	ctrl, kube, _, syncContext := retiredGuardFixture(t)
	ctrl.nodeFilter = omitFirstGuardNode
	ctx := context.Background()
	if err := kube.CoreV1().Pods("test").Delete(ctx, "operand-guard-master-0", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	budgets := kube.PolicyV1().PodDisruptionBudgets("test")
	const name = "operand-guard-pdb"
	budget, err := budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	budget.ResourceVersion = "1"
	if _, err := budgets.Update(ctx, budget, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	resource := policyv1.SchemeGroupVersion.WithResource("poddisruptionbudgets")
	reserved := false
	kube.PrependReactor("list", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		if !reserved {
			current := budget.DeepCopy()
			current.ResourceVersion = "2"
			current.Status.DisruptedPods = map[string]metav1.Time{"operand-guard-master-1": metav1.Now()}
			if err := kube.Tracker().Update(resource, current, "test"); err != nil {
				t.Fatal(err)
			}
			reserved = true
		}
		return false, nil, nil
	})
	kube.PrependReactor("update", "poddisruptionbudgets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		update := action.(clienttesting.UpdateAction).GetObject().(*policyv1.PodDisruptionBudget)
		if update.ResourceVersion != "2" {
			return true, nil, apierrors.NewConflict(resource.GroupResource(), name, errors.New("eviction reserved after budget read"))
		}
		return false, nil, nil
	})
	if err := ctrl.sync(ctx, syncContext); !apierrors.IsConflict(err) {
		t.Fatalf("expected conflict from the intervening eviction, got %v", err)
	}
	current, err := budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if current.Spec.MinAvailable.IntValue() != 3 || len(current.Status.DisruptedPods) != 1 {
		t.Fatalf("expected conservative budget and preserved reservation, got %+v", current)
	}
	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	current, err = budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if current.Spec.MinAvailable.IntValue() != 2 || len(current.Status.DisruptedPods) != 1 {
		t.Fatalf("expected reduction after a new reconcile with the reservation preserved, got %+v", current)
	}
}
