package v1helpers

import (
	"fmt"
	configv1 "github.com/openshift/api/config/v1"
	applyconfigv1 "github.com/openshift/client-go/config/applyconfigurations/config/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/json"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
)

func AreClusterOperatorStatusEquivalent(lhs, rhs *applyconfigv1.ClusterOperatorStatusApplyConfiguration) (bool, error) {
	CanonicalizeClusterOperatorStatus(lhs)
	CanonicalizeClusterOperatorStatus(rhs)
	lhsObj, err := ToClusterOperator(lhs)
	if err != nil {
		return false, err
	}
	rhsObj, err := ToClusterOperator(rhs)
	if err != nil {
		return false, err
	}
	if equality.Semantic.DeepEqual(rhsObj, lhsObj) {
		return true, nil
	}

	return false, nil
}

func ToApplyClusterOperatorRelatedObj(in configv1.ObjectReference) *applyconfigv1.ObjectReferenceApplyConfiguration {
	return applyconfigv1.ObjectReference().WithName(in.Name).WithNamespace(in.Namespace).WithGroup(in.Group).WithResource(in.Resource)
}

// ToStaticPodOperator returns the equivalent typed kind for the applyconfiguration. Due to differences in serialization like
// omitempty on strings versus pointers, the returned values can be slightly different.  This is an expensive way to diff the
// result, but it is an effective one.
func ToClusterOperator(in *applyconfigv1.ClusterOperatorStatusApplyConfiguration) (*configv1.ClusterOperatorStatus, error) {
	if in == nil {
		return nil, nil
	}
	jsonBytes, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize: %w", err)
	}

	ret := &configv1.ClusterOperatorStatus{}
	if err := json.Unmarshal(jsonBytes, ret); err != nil {
		return nil, fmt.Errorf("unable to deserialize: %w", err)
	}

	return ret, nil
}

func SetClusterOperatorApplyConditionsLastTransitionTime(clock clock.PassiveClock, newConditions *[]applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration, oldConditions []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration) {
	if newConditions == nil {
		return
	}

	now := metav1.NewTime(clock.Now())
	for i := range *newConditions {
		newCondition := (*newConditions)[i]

		// if the condition status is the same, then the lastTransitionTime doesn't change
		if existingCondition := FindClusterOperatorApplyCondition(oldConditions, newCondition.Type); existingCondition != nil && ptr.Equal(existingCondition.Status, newCondition.Status) {
			newCondition.LastTransitionTime = existingCondition.LastTransitionTime
		}

		// backstop to handle upgrade case too.  If the newCondition doesn't have a lastTransitionTime it needs something
		if newCondition.LastTransitionTime == nil {
			newCondition.LastTransitionTime = &now
		}

		(*newConditions)[i] = newCondition
	}
}

func FindClusterOperatorApplyCondition(haystack []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration, conditionType *configv1.ClusterStatusConditionType) *applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration {
	for i := range haystack {
		curr := haystack[i]
		if ptr.Equal(curr.Type, conditionType) {
			return &curr
		}
	}

	return nil
}

func CanonicalizeClusterOperatorStatus(obj *applyconfigv1.ClusterOperatorStatusApplyConfiguration) {
	if obj == nil {
		return
	}
	slices.SortStableFunc(obj.Conditions, CompareClusterOperatorConditionByType)
	slices.SortStableFunc(obj.Versions, CompareClusterOperatorVersionsByName)
	slices.SortStableFunc(obj.RelatedObjects, CompareClusterOperatorRelatedObjects)
}

func CompareClusterOperatorConditionByType(a, b applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration) int {
	return strings.Compare(string(ptr.Deref(a.Type, "")), string(ptr.Deref(b.Type, "")))
}

func CompareClusterOperatorVersionsByName(a, b applyconfigv1.OperandVersionApplyConfiguration) int {
	if cmp := strings.Compare(ptr.Deref(a.Name, ""), ptr.Deref(b.Name, "")); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(ptr.Deref(a.Version, ""), ptr.Deref(b.Version, "")); cmp != 0 {
		return cmp
	}
	return 0
}

func CompareClusterOperatorRelatedObjects(a, b applyconfigv1.ObjectReferenceApplyConfiguration) int {
	if cmp := strings.Compare(ptr.Deref(a.Group, ""), ptr.Deref(b.Group, "")); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(ptr.Deref(a.Resource, ""), ptr.Deref(b.Resource, "")); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(ptr.Deref(a.Namespace, ""), ptr.Deref(b.Namespace, "")); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(ptr.Deref(a.Name, ""), ptr.Deref(b.Name, "")); cmp != 0 {
		return cmp
	}
	return 0
}
