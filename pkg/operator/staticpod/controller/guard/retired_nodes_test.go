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
		{name: "two retirements are rejected", filter: func(_ context.Context, nodes []*corev1.Node) ([]*corev1.Node, error) {
			return nodes[2:], nil
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
			kube.PrependReactor("create", "pods/eviction", func(action clienttesting.Action) (bool, runtime.Object, error) {
				if action.(clienttesting.CreateAction).GetObject().(*policyv1.Eviction).Name != "operand-guard-master-0" {
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
				if action.Matches("create", "pods/eviction") && action.(clienttesting.CreateAction).GetObject().(*policyv1.Eviction).Name == pod.Name {
					t.Fatal("guard with unverified identity was evicted")
				}
				if action.Matches("delete", "pods") && action.(clienttesting.DeleteAction).GetName() == pod.Name {
					t.Fatal("guard with unverified identity was deleted")
				}
			}
		})
	}
}

// If a retained guard takes the last eviction slot after the health check,
// admission refuses the outgoing Ready guard. Reconciliation must preserve
// the conservative budget and must never fall back to direct deletion.
func TestRetiredGuardWaitsForEvictionAdmission(t *testing.T) {
	ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
	ctrl.nodeFilter = omitFirstGuardNode
	ctx := context.Background()
	pods := kube.CoreV1().Pods("test")
	unready, err := pods.Get(ctx, "operand-guard-master-3", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unready.Status.Conditions[0].Status = corev1.ConditionFalse
	if _, err := pods.UpdateStatus(ctx, unready, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	budgets := kube.PolicyV1().PodDisruptionBudgets("test")
	budget, err := budgets.Get(ctx, "operand-guard-pdb", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	budget.Status.ExpectedPods = 4
	budget.Status.CurrentHealthy = 4 // The disruption controller has not observed the readiness change.
	budget.Status.DesiredHealthy = 3
	budget.Status.DisruptionsAllowed = 1
	if _, err := budgets.UpdateStatus(ctx, budget, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	refresh()
	const outgoing = "operand-guard-master-0"
	kube.PrependReactor("delete", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		t.Fatalf("unexpected direct delete: %v", action)
		return false, nil, nil
	})
	requested := false
	kube.PrependReactor("create", "pods/eviction", func(action clienttesting.Action) (bool, runtime.Object, error) {
		eviction := action.(clienttesting.CreateAction).GetObject().(*policyv1.Eviction)
		if eviction.Name != outgoing {
			t.Fatalf("unexpected eviction of %q", eviction.Name)
		}
		requested = true
		reserved := budget.DeepCopy()
		reserved.Status.DisruptionsAllowed = 0
		reserved.Status.DisruptedPods = map[string]metav1.Time{"operand-guard-master-1": metav1.Now()}
		if err := kube.Tracker().Update(policyv1.SchemeGroupVersion.WithResource("poddisruptionbudgets"), reserved, reserved.Namespace); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewTooManyRequests("disruption budget exhausted", 0)
	})
	if err := ctrl.sync(ctx, syncContext); err == nil || !requested {
		t.Fatalf("expected eviction rejection, requested=%t, err=%v", requested, err)
	}
	if _, err := kube.CoreV1().Pods("test").Get(ctx, outgoing, metav1.GetOptions{}); err != nil {
		t.Fatalf("outgoing guard after rejected eviction: %v", err)
	}
	budget, err = budgets.Get(ctx, budget.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, reserved := budget.Status.DisruptedPods["operand-guard-master-1"]; !reserved || budget.Spec.MinAvailable.IntValue() != 3 {
		t.Fatalf("expected original budget and retained reservation, got %+v", budget)
	}
}

func TestRetirementRejectsStaleMatchingGuardCount(t *testing.T) {
	ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
	ctrl.nodeFilter = omitFirstGuardNode
	ctx := context.Background()
	pods := kube.CoreV1().Pods("test")
	budgets := kube.PolicyV1().PodDisruptionBudgets("test")
	retained, err := pods.Get(ctx, "operand-guard-master-3", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := pods.Delete(ctx, retained.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	// At this point the PDB counts the outgoing guard and two retained guards.
	budget, err := budgets.Get(ctx, "operand-guard-pdb", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	budget.Generation = 1
	budget.Status = policyv1.PodDisruptionBudgetStatus{
		ObservedGeneration: 1, ExpectedPods: 3, CurrentHealthy: 3, DesiredHealthy: 3,
	}
	if _, err := budgets.Update(ctx, budget, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// The live set now has three retained guards. The PDB still describes
	// the previous set, with the same count and the correct generation.
	outgoing, err := pods.Get(ctx, "operand-guard-master-0", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := pods.Delete(ctx, outgoing.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	retained.UID = "new-retained-guard"
	retained.ResourceVersion = ""
	if _, err := pods.Create(ctx, retained, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	refresh()
	syncErr := ctrl.sync(ctx, syncContext)
	budget, err = budgets.Get(ctx, budget.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	selector, err := metav1.LabelSelectorAsSelector(budget.Spec.Selector)
	if err != nil {
		t.Fatal(err)
	}
	if got := budget.Spec.MinAvailable.IntValue(); got < 3 && selector.Matches(labels.Set(outgoing.Labels)) {
		t.Fatalf("minAvailable reduced to %d while the selector still matches the cached outgoing guard (sync error: %v)", got, syncErr)
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
			kube.PrependReactor("create", "pods/eviction", func(action clienttesting.Action) (bool, runtime.Object, error) {
				eviction := action.(clienttesting.CreateAction).GetObject().(*policyv1.Eviction)
				if eviction.Name != pod.Name {
					return false, nil, nil
				}
				preconditions := eviction.DeleteOptions.Preconditions
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
	for _, mode := range []string{"exactly two healthy", "two unhealthy", "two terminating", "two approved disruptions", "two stale node identities"} {
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
				case "two stale node identities":
					pod.Labels[guardNodeUIDLabel] = "previous-node-uid"
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
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name), Labels: map[string]string{"node-role.kubernetes.io/master": ""}}}
		operand := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operand-" + name, Namespace: "test", Labels: map[string]string{"app": "operand"}}, Spec: corev1.PodSpec{NodeName: name}, Status: corev1.PodStatus{PodIP: ip}}
		pod := resourceread.ReadPodV1OrDie(podTemplate)
		pod.Name, pod.Namespace, pod.Spec.NodeName = getGuardPodName("operand", name), "test", name
		pod.UID, pod.ResourceVersion = types.UID(pod.Name), "1"
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
	// Complete an accepted eviction in the object tracker. Individual tests
	// override this reactor to exercise pending, rejected and conflicting requests.
	kube.PrependReactor("create", "pods/eviction", func(action clienttesting.Action) (bool, runtime.Object, error) {
		eviction := action.(clienttesting.CreateAction).GetObject().(*policyv1.Eviction)
		return true, nil, kube.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), eviction.Namespace, eviction.Name)
	})
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

	ctrl.nodeFilter = omitFirstGuardNode
	kube.PrependReactor("update", "poddisruptionbudgets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		pdb := action.(clienttesting.UpdateAction).GetObject().(*policyv1.PodDisruptionBudget)
		if pdb.Name == budgetName && len(pdb.Spec.Selector.MatchExpressions) != 0 && pdb.Generation == 0 {
			pdb.Generation = 1 // The fake API does not advance spec generations.
		}
		return false, nil, nil
	})
	if err := ctrl.sync(ctx, syncContext); err == nil {
		t.Fatal("expected to wait for the retained selector to be observed")
	}
	pdb, err := budgets.Get(ctx, budgetName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pdb.Spec.MinAvailable.IntValue() != frozenGuardMinimum || len(pdb.Spec.Selector.MatchExpressions) == 0 {
		t.Fatalf("expected the retained selector with the frozen minimum, got %+v", pdb.Spec)
	}
	pdb.Status.ObservedGeneration = pdb.Generation
	if _, err := budgets.UpdateStatus(ctx, pdb, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	refresh()
	restarted := *ctrl
	if err := restarted.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	pdb, err = budgets.Get(ctx, budgetName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := pdb.Spec.MinAvailable.IntValue(); got != 2 {
		t.Fatalf("minAvailable=%d, want 2 after selector observation", got)
	}
	if _, err := kube.CoreV1().Pods("test").Get(ctx, "operand-guard-master-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("retired guard was recreated: %v", err)
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
	conflict := apierrors.NewConflict(resource.GroupResource(), name, errors.New("eviction reserved after budget read"))
	const retainedGuard = "operand-guard-master-1"
	reserved := false
	kube.PrependReactor("update", "poddisruptionbudgets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		update := action.(clienttesting.UpdateAction).GetObject().(*policyv1.PodDisruptionBudget)
		if update.Name != name || update.Spec.MinAvailable.IntValue() != 2 || reserved {
			return false, nil, nil
		}
		obj, err := kube.Tracker().Get(resource, "test", name)
		if err != nil {
			t.Fatal(err)
		}
		current := obj.(*policyv1.PodDisruptionBudget).DeepCopy()
		if current.Spec.MinAvailable.IntValue() != frozenGuardMinimum || update.ResourceVersion != current.ResourceVersion {
			t.Fatalf("expected reduction from the frozen budget at version %q, got %+v", current.ResourceVersion, update)
		}
		current.ResourceVersion = "2"
		current.Status.DisruptedPods = map[string]metav1.Time{retainedGuard: metav1.Now()}
		if err := kube.Tracker().Update(resource, current, "test"); err != nil {
			t.Fatal(err)
		}
		reserved = true
		return true, nil, conflict
	})
	if err := ctrl.sync(ctx, syncContext); !errors.Is(err, conflict) || !reserved {
		t.Fatalf("expected conflict from the intervening eviction, got %v", err)
	}
	current, err := budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := current.Status.DisruptedPods[retainedGuard]; !ok || current.Spec.MinAvailable.IntValue() != frozenGuardMinimum {
		t.Fatalf("expected frozen budget and preserved reservation, got %+v", current)
	}
	if err := ctrl.sync(ctx, syncContext); err == nil {
		t.Fatal("expected to wait for the accepted eviction to settle")
	}
	current, err = budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := current.Status.DisruptedPods[retainedGuard]; !ok || current.Spec.MinAvailable.IntValue() != frozenGuardMinimum {
		t.Fatalf("retry changed the frozen budget or reservation: %+v", current)
	}
	current.Status.DisruptedPods = nil
	if _, err := budgets.UpdateStatus(ctx, current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	current, err = budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if current.Spec.MinAvailable.IntValue() != 2 {
		t.Fatalf("expected reduction after the reservation settled, got %+v", current.Spec)
	}
}

func TestRetirementRestoresMissingPrimaryBudget(t *testing.T) {
	ctrl, kube, _, syncContext := retiredGuardFixture(t)
	ctx := context.Background()
	budgets := kube.PolicyV1().PodDisruptionBudgets("test")
	const name = "operand-guard-pdb"
	if err := kube.CoreV1().Pods("test").Delete(ctx, "operand-guard-master-0", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	ctrl.nodeFilter = omitFirstGuardNode
	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	if err := budgets.Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	ctrl.nodeFilter = func(_ context.Context, nodes []*corev1.Node) ([]*corev1.Node, error) {
		return nodes, nil
	}
	if err := ctrl.sync(ctx, syncContext); err == nil {
		t.Fatal("expected recovery to wait for observation of the restored budget")
	}
	budget, err := budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if budget.Spec.MinAvailable.IntValue() != frozenGuardMinimum || budget.Spec.Selector.MatchLabels["app"] != "guard" {
		t.Fatalf("expected broad frozen coverage during recovery, got %+v", budget.Spec)
	}
	if _, err := budgets.Get(ctx, name+"-unidentified", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected temporary coverage to remain during recovery: %v", err)
	}
}

func TestRetirementRetriesWhenOutgoingGuardReappears(t *testing.T) {
	ctrl, kube, _, syncContext := retiredGuardFixture(t)
	ctrl.nodeFilter = omitFirstGuardNode
	ctx := context.Background()
	pods := kube.CoreV1().Pods("test")
	outgoing, err := pods.Get(ctx, "operand-guard-master-0", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	if _, err := pods.Create(ctx, outgoing, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	budgets := kube.PolicyV1().PodDisruptionBudgets("test")
	const name = "operand-guard-pdb"
	budget, err := budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	budget.Status.ExpectedPods = 4
	if _, err := budgets.UpdateStatus(ctx, budget, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.sync(ctx, syncContext); err == nil {
		t.Fatal("expected recovery before retry")
	}
	if err := ctrl.sync(ctx, syncContext); err == nil {
		t.Fatal("expected to wait for the retained guard count after eviction")
	}
	budget, err = budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if budget.Spec.MinAvailable.IntValue() != frozenGuardMinimum {
		t.Fatalf("expected a frozen budget while the count is stale, got %+v", budget.Spec)
	}
	budget.Status.ExpectedPods = 3
	if _, err := budgets.UpdateStatus(ctx, budget, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	if _, err := pods.Get(ctx, outgoing.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("outgoing guard still present after retry: %v", err)
	}
	budget, err = budgets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if budget.Spec.MinAvailable.IntValue() != 2 {
		t.Fatalf("expected retirement to finish, got %+v", budget.Spec)
	}
}

func TestDisablingRetirementAwareGuardsRemovesBothBudgets(t *testing.T) {
	ctrl, kube, refresh, syncContext := retiredGuardFixture(t)
	ctrl.nodeFilter = omitFirstGuardNode
	ctx := context.Background()
	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	budgets := kube.PolicyV1().PodDisruptionBudgets("test")
	const primary = "operand-guard-pdb"
	const fallback = primary + unidentifiedGuardBudgetSuffix
	if _, err := budgets.Get(ctx, fallback, metav1.GetOptions{}); err != nil {
		t.Fatalf("expected temporary budget before disabling guards: %v", err)
	}
	ctrl.createConditionalFunc = func() (bool, bool, error) { return false, true, nil }
	refresh()
	if err := ctrl.sync(ctx, syncContext); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{primary, fallback} {
		if _, err := budgets.Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Errorf("expected budget %s to be removed: %v", name, err)
		}
	}
}
