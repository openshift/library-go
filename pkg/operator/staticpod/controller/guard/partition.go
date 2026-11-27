package guard

import (
	"context"
	"fmt"
	"sort"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const guardNodeUIDLabel = "guard.operator.openshift.io/node-uid"
const unidentifiedGuardBudgetSuffix = "-unidentified"
const frozenGuardMinimum = 2147483647

func guardIdentitySelector(ids []string, op metav1.LabelSelectorOperator) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"app": "guard"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: guardNodeUIDLabel, Operator: op, Values: ids}}}
}

func frozenGuardSpec(spec policyv1.PodDisruptionBudgetSpec) policyv1.PodDisruptionBudgetSpec {
	minimum := intstr.FromInt(frozenGuardMinimum)
	policy := policyv1.IfHealthyBudget
	spec.MinAvailable = &minimum
	spec.MaxUnavailable = nil
	spec.UnhealthyPodEvictionPolicy = &policy
	return spec
}

// Keep the original PDB object and disruptedPods reservations. Recreating it or
// moving retained guards to another budget would lose accepted evictions.
func (c *GuardController) freezeGuardBudget(ctx context.Context, recorder events.Recorder) error {
	b, err := c.pdbGetter.PodDisruptionBudgets(c.targetNamespace).Get(ctx, getGuardPDBName(c.podResourcePrefix), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		b = c.guardBudget(nil)
	} else if err != nil {
		return err
	}
	b = b.DeepCopy()
	b.Spec = frozenGuardSpec(b.Spec)
	_, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, b)
	return err
}

// Expand coverage before moving the fallback boundary. The union covers both
// old and new identities throughout membership changes. Broad legacy coverage
// stays broad until the complementary PDB exists.
func unionGuardSelector(previous *metav1.LabelSelector, ids []string) (*metav1.LabelSelector, error) {
	if previous == nil || len(previous.MatchLabels) != 1 || previous.MatchLabels["app"] != "guard" {
		return nil, fmt.Errorf("unexpected guard budget selector")
	}
	if len(previous.MatchExpressions) == 0 {
		return previous.DeepCopy(), nil
	}
	if len(previous.MatchExpressions) != 1 {
		return nil, fmt.Errorf("unexpected guard identity selector")
	}
	e := previous.MatchExpressions[0]
	if e.Key != guardNodeUIDLabel || e.Operator != metav1.LabelSelectorOpIn {
		return nil, fmt.Errorf("unexpected guard identity constraint")
	}
	set := map[string]bool{}
	for _, id := range e.Values {
		set[id] = true
	}
	for _, id := range ids {
		set[id] = true
	}
	union := []string{}
	for id := range set {
		union = append(union, id)
	}
	sort.Strings(union)
	return guardIdentitySelector(union, metav1.LabelSelectorOpIn), nil
}

func observedGuardBudget(b *policyv1.PodDisruptionBudget) bool {
	return b.Status.ObservedGeneration >= b.Generation
}

func (c *GuardController) reconcileGuardPartition(ctx context.Context, all, retained, retired []*corev1.Node, recorder events.Recorder) error {
	if len(retired) == 0 {
		return c.restoreOrdinaryGuardBudget(ctx, all, recorder)
	}
	// HA retirement is the only opt-in contract currently supported.
	if len(retained) < 3 {
		if err := c.freezeGuardBudget(ctx, recorder); err != nil {
			return err
		}
		return fmt.Errorf("guard partition requires at least three retained Nodes")
	}
	ids := []string{}
	retainedUIDs := map[string]string{}
	allUIDs := map[string]string{}
	seen := map[string]bool{}
	for _, node := range all {
		if node.UID == "" || seen[string(node.UID)] {
			if err := c.freezeGuardBudget(ctx, recorder); err != nil {
				return err
			}
			return fmt.Errorf("missing or duplicate guard Node identity")
		}
		seen[string(node.UID)] = true
		allUIDs[node.Name] = string(node.UID)
	}
	for _, node := range retained {
		ids = append(ids, string(node.UID))
		retainedUIDs[node.Name] = string(node.UID)
	}
	sort.Strings(ids)
	desired := c.guardBudget(retained)
	desired.Spec.Selector = guardIdentitySelector(ids, metav1.LabelSelectorOpIn)
	fallback := desired.DeepCopy()
	fallback.Name += unidentifiedGuardBudgetSuffix
	fallback.Spec = frozenGuardSpec(fallback.Spec)
	fallback.Spec.Selector = guardIdentitySelector(ids, metav1.LabelSelectorOpNotIn)
	client := c.pdbGetter.PodDisruptionBudgets(c.targetNamespace)
	current, err := client.Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		current, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, c.guardBudget(all))
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	other, err := client.Get(ctx, fallback.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		other = nil
	} else if err != nil {
		return err
	}
	if other == nil && (current.Spec.Selector == nil || current.Spec.Selector.MatchLabels["app"] != "guard") {
		if _, _, err := resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, c.guardBudget(all)); err != nil {
			return err
		}
		return fmt.Errorf("waiting for repaired guard budget before retirement")
	}
	if err := c.evictOutgoingGuards(ctx, all, retained, retired, current, c.guardBudget(all), other, recorder); err != nil {
		return err
	}
	partitionReady := other != nil && equality.Semantic.DeepEqual(other.Spec, fallback.Spec) && equality.Semantic.DeepEqual(current.Spec, desired.Spec)
	if !partitionReady {
		transitional := current.DeepCopy()
		transitional.Spec = frozenGuardSpec(transitional.Spec)
		transitional.Spec.Selector, err = unionGuardSelector(current.Spec.Selector, ids)
		if err != nil {
			if freezeErr := c.freezeGuardBudget(ctx, recorder); freezeErr != nil {
				return freezeErr
			}
			return err
		}
		current, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, transitional)
		if err != nil {
			return err
		}
		if !observedGuardBudget(current) {
			return fmt.Errorf("waiting for frozen guard budget observation")
		}
		// Do not change the selector while an approved eviction is pending.
		// A retained Pod whose new identity label is not in the disruption
		// cache yet would disappear from that controller's selected set, which
		// drops its reservation. Keep the old selector until reservations clear.
		if len(current.Status.DisruptedPods) != 0 {
			return fmt.Errorf("waiting for accepted guard evictions to settle")
		}
	}

	// Add identity to existing retained guards even on cordoned Nodes. Never
	// overwrite an identity: name reuse and mismatches must remain protected.
	pods, err := c.podGetter.Pods(c.targetNamespace).List(ctx, metav1.ListOptions{LabelSelector: "app=guard"})
	if err != nil {
		return err
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		uid := pod.Labels[guardNodeUIDLabel]
		if uid != "" && (allUIDs[pod.Spec.NodeName] != uid || pod.Name != getGuardPodName(c.podResourcePrefix, pod.Spec.NodeName)) {
			if err := c.freezeGuardBudget(ctx, recorder); err != nil {
				return err
			}
			return fmt.Errorf("guard identity mismatch")
		}
		wanted, ok := retainedUIDs[pod.Spec.NodeName]
		if !ok {
			continue
		}
		if pod.Name != getGuardPodName(c.podResourcePrefix, pod.Spec.NodeName) {
			if err := c.freezeGuardBudget(ctx, recorder); err != nil {
				return err
			}
			return fmt.Errorf("unexpected retained guard name")
		}
		if uid == "" {
			copy := pod.DeepCopy()
			copy.Labels[guardNodeUIDLabel] = wanted
			if _, err := c.podGetter.Pods(c.targetNamespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}
	if !partitionReady {
		other, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, fallback)
		if err != nil {
			return err
		}
		if !observedGuardBudget(other) {
			return fmt.Errorf("waiting for unidentified guard budget observation")
		}
		held := desired.DeepCopy()
		held.Spec = frozenGuardSpec(held.Spec)
		current, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, held)
		if err != nil {
			return err
		}
		if !observedGuardBudget(current) {
			return fmt.Errorf("waiting for retained guard budget observation")
		}
		updated := current.DeepCopy()
		updated.Spec = desired.Spec
		if _, err := client.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("reduce retained guard budget: %w", err)
		}
	}
	return nil
}

// Restore the original, broad policy once retirement no longer excludes any
// selected Node. This also provides the preparation barrier for a rollback:
// old controllers create unlabeled guards and cannot clean up our fallback.
// Do not remove fallback protection until the broad budget is observed frozen.
func (c *GuardController) restoreOrdinaryGuardBudget(ctx context.Context, nodes []*corev1.Node, recorder events.Recorder) error {
	client := c.pdbGetter.PodDisruptionBudgets(c.targetNamespace)
	desired := c.guardBudget(nodes)
	current, err := client.Get(ctx, desired.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if apierrors.IsNotFound(err) {
		current = nil
	}
	fallback, err := client.Get(ctx, desired.Name+unidentifiedGuardBudgetSuffix, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if apierrors.IsNotFound(err) {
		fallback = nil
	}
	// Fresh clusters and completed transitions use the baseline policy without
	// introducing a second budget or an identity-dependent rollback contract.
	if fallback == nil && (current == nil || equality.Semantic.DeepEqual(current.Spec.Selector, desired.Spec.Selector)) {
		_, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, desired)
		return err
	}
	if current == nil {
		current = desired.DeepCopy()
		current.Spec = frozenGuardSpec(current.Spec)
	}
	// Live inventory must contain only one correctly bound guard per selected
	// Node. An outgoing/unknown guard must not supply capacity to a broad budget.
	identities := map[string]string{}
	for _, node := range nodes {
		if node.UID == "" {
			return fmt.Errorf("missing Node identity during guard restoration")
		}
		identities[node.Name] = string(node.UID)
	}
	pods, err := c.podGetter.Pods(c.targetNamespace).List(ctx, metav1.ListOptions{LabelSelector: "app=guard"})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		uid, found := identities[pod.Spec.NodeName]
		if !found || pod.Name != getGuardPodName(c.podResourcePrefix, pod.Spec.NodeName) ||
			(pod.Labels[guardNodeUIDLabel] != "" && pod.Labels[guardNodeUIDLabel] != uid) {
			if err := c.freezeGuardBudget(ctx, recorder); err != nil {
				return err
			}
			return fmt.Errorf("waiting for outgoing or unidentified guards before ordinary policy restoration")
		}
	}
	// First freeze without changing the selector. Preserve reservations until
	// the disruption controller has accounted for accepted evictions.
	held := current.DeepCopy()
	held.Spec = frozenGuardSpec(held.Spec)
	current, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, held)
	if err != nil {
		return err
	}
	if !observedGuardBudget(current) {
		return fmt.Errorf("waiting for frozen restoration budget observation")
	}
	if len(current.Status.DisruptedPods) != 0 {
		return fmt.Errorf("waiting for accepted guard evictions to settle")
	}
	// Broad frozen coverage protects unlabeled old-controller guards before
	// removing the complementary budget. Keep the original budget object.
	held = desired.DeepCopy()
	held.Spec = frozenGuardSpec(held.Spec)
	current, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, held)
	if err != nil {
		return err
	}
	if !observedGuardBudget(current) {
		return fmt.Errorf("waiting for broad restoration budget observation")
	}
	if current.Status.ExpectedPods != int32(len(pods.Items)) {
		return fmt.Errorf("waiting for broad guard inventory observation")
	}
	if fallback != nil {
		if err := client.Delete(ctx, fallback.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &fallback.UID, ResourceVersion: &fallback.ResourceVersion}}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	_, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, desired)
	return err
}

func (c *GuardController) evictOutgoingGuards(ctx context.Context, all, retained, retired []*corev1.Node, current, ordinary, fallback *policyv1.PodDisruptionBudget, recorder events.Recorder) error {
	restoreProtection := func(cause error) error {
		var err error
		if fallback == nil && equality.Semantic.DeepEqual(current.Spec.Selector, ordinary.Spec.Selector) {
			_, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, ordinary)
		} else {
			err = c.freezeGuardBudget(ctx, recorder)
		}
		return utilerrors.NewAggregate([]error{cause, err})
	}
	for _, node := range retired {
		p, err := c.podGetter.Pods(c.targetNamespace).Get(ctx, getGuardPodName(c.podResourcePrefix, node.Name), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return restoreProtection(err)
		}
		if p.Spec.NodeName != node.Name || p.Labels["app"] != "guard" || p.UID == "" || p.ResourceVersion == "" {
			return restoreProtection(fmt.Errorf("incomplete retired guard identity"))
		}
		if label := p.Labels[guardNodeUIDLabel]; label != "" && label != string(node.UID) {
			return restoreProtection(fmt.Errorf("retired guard identity changed"))
		}
		if fallback != nil || !equality.Semantic.DeepEqual(current.Spec.Selector, ordinary.Spec.Selector) {
			if err := c.restoreOrdinaryGuardBudget(ctx, all, recorder); err != nil {
				return err
			}
			return fmt.Errorf("restored the original guard budget before retrying eviction of %s", p.Name)
		}
		if !equality.Semantic.DeepEqual(current.Spec, ordinary.Spec) || !observedGuardBudget(current) {
			current, _, err = resourceapply.ApplyPodDisruptionBudget(ctx, c.pdbGetter, recorder, ordinary)
			if err != nil {
				return err
			}
			if !observedGuardBudget(current) {
				return fmt.Errorf("waiting for the original guard budget before eviction")
			}
		}
		if err := c.checkRetainedGuardHealth(ctx, retained, current); err != nil {
			return err
		}
		pods := c.podGetter.Pods(c.targetNamespace)
		eviction := &policyv1.Eviction{
			ObjectMeta:    metav1.ObjectMeta{Name: p.Name, Namespace: p.Namespace},
			DeleteOptions: &metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &p.UID, ResourceVersion: &p.ResourceVersion}},
		}
		if err := pods.EvictV1(ctx, eviction); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if _, err := pods.Get(ctx, p.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			if err != nil {
				return err
			}
			return fmt.Errorf("waiting for outgoing guard %s to disappear", p.Name)
		}
		recorder.Eventf("GuardRetired", "Removed guard for a verified retired operand")
	}
	return nil
}

func (c *GuardController) checkRetainedGuardHealth(ctx context.Context, retained []*corev1.Node, current *policyv1.PodDisruptionBudget) error {
	pods, err := c.podGetter.Pods(c.targetNamespace).List(ctx, metav1.ListOptions{LabelSelector: "app=guard"})
	if err != nil {
		return err
	}
	retainedNames := map[string]bool{}
	for _, node := range retained {
		retainedNames[node.Name] = true
	}
	healthy := map[string]bool{}
	for _, pod := range pods.Items {
		if !retainedNames[pod.Spec.NodeName] || pod.Name != getGuardPodName(c.podResourcePrefix, pod.Spec.NodeName) || pod.DeletionTimestamp != nil {
			continue
		}
		if _, disrupted := current.Status.DisruptedPods[pod.Name]; disrupted {
			continue
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				healthy[pod.Spec.NodeName] = true
			}
		}
	}
	minimum := c.guardBudget(retained).Spec.MinAvailable.IntValue()
	if len(healthy) < minimum {
		return fmt.Errorf("retained guards are below the post-retirement minimum: healthy=%d required=%d", len(healthy), minimum)
	}
	return nil
}
