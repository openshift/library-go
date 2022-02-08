package installer

import (
	operatorv1 "github.com/openshift/api/operator/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"math"
	"strconv"
	"strings"
)

const (
	defaultRevisionLimit = int32(5)
)

func defaultedLimits(operatorSpec *operatorv1.StaticPodOperatorSpec) (int, int) {
	failedRevisionLimit := defaultRevisionLimit
	succeededRevisionLimit := defaultRevisionLimit
	if operatorSpec.FailedRevisionLimit != 0 {
		failedRevisionLimit = operatorSpec.FailedRevisionLimit
	}
	if operatorSpec.SucceededRevisionLimit != 0 {
		succeededRevisionLimit = operatorSpec.SucceededRevisionLimit
	}
	return int(failedRevisionLimit), int(succeededRevisionLimit)
}

// int32Range returns range of int32 from upper-num+1 to upper.
func int32RangeBelowOrEqual(upper int32, num int) []int32 {
	ret := make([]int32, 0, num)
	for i := 0; i < num; i++ {
		value := upper - int32(num) + 1 + int32(i)
		if value > 0 {
			ret = append(ret, value)
		}
	}
	return ret
}

func maxLimit(a, b int) int {
	if a < 0 || b < 0 {
		return -1
	}
	if a > b {
		return a
	}
	return b
}

// revisionsToKeep approximates the set of revisions to keep: spec.failedRevisionsLimit for failed revisions,
// spec.succeededRevisionsLimit for succeed revisions (for all nodes). The approximation goes by:
// - don't prune LatestAvailableRevision and the max(spec.failedRevisionLimit, spec.succeededRevisionLimit) - 1 revisions before it.
// - don't prune a node's CurrentRevision and the spec.succeededRevisionLimit - 1 revisions before it.
// - don't prune a node's TargetRevision and the spec.failedRevisionLimit - 1 revisions before it.
// - don't prune a node's LastFailedRevision and the spec.failedRevisionLimit - 1 revisions before it.
func revisionsToKeep(status *operatorv1.StaticPodOperatorStatus, failedLimit, succeededLimit int) (all bool, keep sets.Int32) {
	// find oldest where we are sure it cannot fail anymore (i.e. = currentRevision
	var oldestSucceeded int32 = math.MaxInt32
	for _, ns := range status.NodeStatuses {
		if ns.CurrentRevision < oldestSucceeded {
			oldestSucceeded = ns.CurrentRevision
		}
	}

	if failedLimit == -1 || succeededLimit == -1 {
		return true, nil // all because we don't know about failure or success
	}

	keep = sets.Int32{}
	if oldestSucceeded < status.LatestAvailableRevision {
		keep.Insert(int32RangeBelowOrEqual(status.LatestAvailableRevision, maxLimit(failedLimit, succeededLimit))...) // max because we don't know about failure or success
	} // otherwise all nodes are on LatestAvailableRevision already. Then there is no fail potential.

	for _, ns := range status.NodeStatuses {
		if ns.CurrentRevision > 0 {
			keep.Insert(int32RangeBelowOrEqual(ns.CurrentRevision, succeededLimit)...)
		}
		if ns.TargetRevision > 0 {
			keep.Insert(int32RangeBelowOrEqual(ns.TargetRevision, maxLimit(failedLimit, succeededLimit))...) // max because we don't know about failure or success
		}
		if ns.LastFailedRevision > 0 {
			keep.Insert(int32RangeBelowOrEqual(ns.LastFailedRevision, failedLimit)...)
		}
	}

	if keep.Len() > 0 && keep.List()[0] == 1 && keep.List()[keep.Len()-1] == status.LatestAvailableRevision {
		return true, nil
	}

	return false, keep
}

func revisionsToString(revisions []int32) string {
	values := []string{}
	for _, id := range revisions {
		value := strconv.Itoa(int(id))
		values = append(values, value)
	}
	return strings.Join(values, ",")
}
