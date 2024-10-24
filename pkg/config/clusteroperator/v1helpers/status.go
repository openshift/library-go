package v1helpers

import (
	"bytes"
	"fmt"
	applyconfigv1 "github.com/openshift/client-go/config/applyconfigurations/config/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/utils/ptr"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
)

// FindStatusCondition finds the conditionType in conditions.
func FindStatusCondition(conditions []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration, conditionType *configv1.ClusterStatusConditionType) *applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration {
	for i := range conditions {
		if ptr.Deref(conditions[i].Type, "") == ptr.Deref(conditionType, "") {
			return &conditions[i]
		}
	}

	return nil
}

// GetStatusDiff returns a string representing change in condition status in human readable form.
func GetStatusDiff(oldStatus, newStatus *applyconfigv1.ClusterOperatorStatusApplyConfiguration) string {
	switch {
	case oldStatus == nil && newStatus == nil:
	case oldStatus != nil && newStatus == nil:
		return "status was removed"
	}
	messages := []string{}
	for _, newCondition := range newStatus.Conditions {
		if oldStatus == nil {
			messages = append(messages, fmt.Sprintf("%s set to %s (%q)", ptr.Deref(newCondition.Type, ""), ptr.Deref(newCondition.Status, ""), ptr.Deref(newCondition.Message, "")))
			continue
		}
		existingStatusCondition := FindStatusCondition(oldStatus.Conditions, newCondition.Type)
		if existingStatusCondition == nil {
			messages = append(messages, fmt.Sprintf("%s set to %s (%q)", ptr.Deref(newCondition.Type, ""), ptr.Deref(newCondition.Status, ""), ptr.Deref(newCondition.Message, "")))
			continue
		}
		if ptr.Deref(existingStatusCondition.Status, "") != ptr.Deref(newCondition.Status, "") {
			messages = append(messages, fmt.Sprintf("%s changed from %s to %s (%q)", ptr.Deref(existingStatusCondition.Type, ""), ptr.Deref(existingStatusCondition.Status, ""), ptr.Deref(newCondition.Status, ""), ptr.Deref(newCondition.Message, "")))
			continue
		}
		existingMessage := strings.TrimPrefix(ptr.Deref(existingStatusCondition.Message, ""), "\ufeff")
		newMessage := strings.TrimPrefix(ptr.Deref(newCondition.Message, ""), "\ufeff")
		if existingMessage != newMessage {
			messages = append(messages, fmt.Sprintf("%s message changed from %q to %q", ptr.Deref(existingStatusCondition.Type, ""), existingMessage, newMessage))
		}
	}
	if oldStatus != nil {
		for _, oldCondition := range oldStatus.Conditions {
			// This should not happen. It means we removed old condition entirely instead of just changing its status
			if c := FindStatusCondition(newStatus.Conditions, oldCondition.Type); c == nil {
				messages = append(messages, fmt.Sprintf("%s was removed", ptr.Deref(oldCondition.Type, "")))
			}
		}
	}

	if oldStatus != nil {
		if !equality.Semantic.DeepEqual(oldStatus.RelatedObjects, newStatus.RelatedObjects) {
			messages = append(messages, fmt.Sprintf("status.relatedObjects changed from %#v to %#v", oldStatus.RelatedObjects, newStatus.RelatedObjects))
		}
		if !equality.Semantic.DeepEqual(oldStatus.Extension, newStatus.Extension) {
			messages = append(messages, fmt.Sprintf("status.extension changed from %#v to %#v", oldStatus.Extension, newStatus.Extension))
		}
		if !equality.Semantic.DeepEqual(oldStatus.Versions, newStatus.Versions) {
			messages = append(messages, fmt.Sprintf("status.versions changed from %#v to %#v", oldStatus.Versions, newStatus.Versions))
		}
	}

	if len(messages) == 0 {
		// ignore errors
		originalJSON := &bytes.Buffer{}
		json.NewEncoder(originalJSON).Encode(oldStatus)
		newJSON := &bytes.Buffer{}
		json.NewEncoder(newJSON).Encode(newStatus)
		messages = append(messages, diff.StringDiff(originalJSON.String(), newJSON.String()))
	}

	return strings.Join(messages, ",")
}

// IsStatusConditionTrue returns true when the conditionType is present and set to `configv1.ConditionTrue`
func IsStatusConditionTrue(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType) bool {
	return IsStatusConditionPresentAndEqual(conditions, conditionType, configv1.ConditionTrue)
}

// IsStatusConditionFalse returns true when the conditionType is present and set to `configv1.ConditionFalse`
func IsStatusConditionFalse(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType) bool {
	return IsStatusConditionPresentAndEqual(conditions, conditionType, configv1.ConditionFalse)
}

// IsStatusConditionPresentAndEqual returns true when conditionType is present and equal to status.
func IsStatusConditionPresentAndEqual(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType, status configv1.ConditionStatus) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status == status
		}
	}
	return false
}

// IsStatusConditionNotIn returns true when the conditionType does not match the status.
func IsStatusConditionNotIn(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType, status ...configv1.ConditionStatus) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			for _, s := range status {
				if s == condition.Status {
					return false
				}
			}
			return true
		}
	}
	return true
}
