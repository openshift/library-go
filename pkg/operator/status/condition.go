package status

import (
	"fmt"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	configv1helpers "github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
)

// UnionCondition returns a single operator condition that is the union of multiple operator conditions.
//
// If inertia is non-nil, then resist returning a condition with a status opposite the happy condition status.
func UnionCondition(conditionType configv1.ClusterStatusConditionType, inertia Inertia, allConditions ...operatorv1.OperatorCondition) operatorv1.OperatorCondition {
	var oppositeConditionStatus operatorv1.ConditionStatus

	happyConditionStatus, ok := configv1helpers.HappyConditionStatus[conditionType]
	if !ok {
		panic(fmt.Sprintf("no happy condition status for %q", conditionType))
	}
	defaultConditionStatus := operatorv1.ConditionStatus(happyConditionStatus)
	if defaultConditionStatus == operatorv1.ConditionTrue {
		oppositeConditionStatus = operatorv1.ConditionFalse
	} else {
		oppositeConditionStatus = operatorv1.ConditionTrue
	}

	interestingConditions := []operatorv1.OperatorCondition{}
	badConditions := []operatorv1.OperatorCondition{}
	badConditionStatus := operatorv1.ConditionUnknown
	for _, condition := range allConditions {
		if strings.HasSuffix(condition.Type, string(conditionType)) {
			interestingConditions = append(interestingConditions, condition)

			if condition.Status != defaultConditionStatus {
				badConditions = append(badConditions, condition)
				if condition.Status == oppositeConditionStatus {
					badConditionStatus = oppositeConditionStatus
				}
			}
		}
	}

	unionedCondition := operatorv1.OperatorCondition{Type: string(conditionType), Status: operatorv1.ConditionUnknown}
	if len(interestingConditions) == 0 {
		unionedCondition.Status = operatorv1.ConditionUnknown
		unionedCondition.Reason = "NoData"
		return unionedCondition
	}

	var elderBadConditions []operatorv1.OperatorCondition
	if inertia == nil {
		elderBadConditions = badConditions
	} else {
		now := time.Now()
		for _, condition := range badConditions {
			if condition.LastTransitionTime.Time.Before(now.Add(-inertia(condition))) {
				elderBadConditions = append(elderBadConditions, condition)
			}
		}
	}

	if len(elderBadConditions) == 0 {
		unionedCondition.Status = defaultConditionStatus
		unionedCondition.Message = unionMessage(interestingConditions)
		unionedCondition.Reason = "AsExpected"
		unionedCondition.LastTransitionTime = latestTransitionTime(interestingConditions)

		return unionedCondition
	}

	// at this point we have bad conditions
	unionedCondition.Status = badConditionStatus
	unionedCondition.Message = unionMessage(badConditions)
	unionedCondition.Reason = unionReason(conditionType, badConditions)
	unionedCondition.LastTransitionTime = latestTransitionTime(badConditions)

	return unionedCondition
}

// UnionClusterCondition returns a single cluster operator condition that is the union of multiple operator conditions.
//
// If inertia is non-nil, then resist returning a condition with a status opposite the happy condition status.
func UnionClusterCondition(conditionType configv1.ClusterStatusConditionType, inertia Inertia, allConditions ...operatorv1.OperatorCondition) configv1.ClusterOperatorStatusCondition {
	cnd := UnionCondition(conditionType, inertia, allConditions...)
	return OperatorConditionToClusterOperatorCondition(cnd)
}

func OperatorConditionToClusterOperatorCondition(condition operatorv1.OperatorCondition) configv1.ClusterOperatorStatusCondition {
	return configv1.ClusterOperatorStatusCondition{
		Type:               configv1.ClusterStatusConditionType(condition.Type),
		Status:             configv1.ConditionStatus(condition.Status),
		LastTransitionTime: condition.LastTransitionTime,
		Reason:             condition.Reason,
		Message:            condition.Message,
	}
}
func latestTransitionTime(conditions []operatorv1.OperatorCondition) metav1.Time {
	latestTransitionTime := metav1.Time{}
	for _, condition := range conditions {
		if latestTransitionTime.Before(&condition.LastTransitionTime) {
			latestTransitionTime = condition.LastTransitionTime
		}
	}
	return latestTransitionTime
}

func uniq(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	j := 0
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		s[j] = v
		j++
	}
	return s[:j]
}

func unionMessage(conditions []operatorv1.OperatorCondition) string {
	messages := []string{}
	for _, condition := range conditions {
		if len(condition.Message) == 0 {
			continue
		}
		for _, message := range uniq(strings.Split(condition.Message, "\n")) {
			messages = append(messages, fmt.Sprintf("%s: %s", condition.Type, message))
		}
	}
	return strings.Join(messages, "\n")
}

func unionReason(unionConditionType configv1.ClusterStatusConditionType, conditions []operatorv1.OperatorCondition) string {
	typeReasons := []string{}
	for _, curr := range conditions {
		currType := curr.Type[:len(curr.Type)-len(unionConditionType)]
		if len(curr.Reason) > 0 {
			typeReasons = append(typeReasons, currType+"_"+curr.Reason)
		} else {
			typeReasons = append(typeReasons, currType)
		}
	}
	sort.Strings(typeReasons)
	return strings.Join(typeReasons, "::")
}
