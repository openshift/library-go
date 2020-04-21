package factory

import (
	"fmt"
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/operator/v1helpers"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

type degradedError struct {
	conditionError
}

type unavailableError struct {
	conditionError
}

type notUpgradeableError struct {
	conditionError
}

// NewDegradedError returns an error that will cause the operator to go to Degraded=True state if returned from the sync() function.
func (syncContext) NewDegradedConditionError(condType, reason, message string) error {
	if !strings.HasSuffix(condType, "Degraded") {
		condType += "Degraded"
	}
	return &degradedError{conditionError{condType: condType, reason: reason, message: message}}
}

// NewAvailableError returns an error that will cause the operator to go to Available=False state if returned from the sync() function.
func (syncContext) NewAvailableConditionError(condType, reason, message string) error {
	if !strings.HasSuffix(condType, "Available") {
		condType += "Available"
	}
	return &unavailableError{conditionError{condType: condType, reason: reason, message: message}}
}

// NewUpgradeableError returns an error that will cause the operator to go to Upgradeable=False state if returned from the sync() function.
func (syncContext) NewUpgradeableConditionError(condType, reason, message string) error {
	if !strings.HasSuffix(condType, "Upgradeable") {
		condType += "Upgradeable"
	}
	return &notUpgradeableError{conditionError{condType: condType, reason: reason, message: message}}
}

// IsDegradedConditionError returns true if error passed indicates that operator should report Degraded=True.
func IsDegradedConditionError(err error) bool {
	if err == nil {
		return false
	}
	if c, ok := err.(*conditionError); ok && strings.HasSuffix(c.condType, "Degraded") {
		return true
	}
	_, ok := err.(*degradedError)
	return ok
}

// IsAvailableConditionError returns true if error passed indicates that operator should report Available=False.
func IsAvailableConditionError(err error) bool {
	if err == nil {
		return false
	}
	if c, ok := err.(*conditionError); ok && strings.HasSuffix(c.condType, "Available") {
		return true
	}
	_, ok := err.(*unavailableError)
	return ok
}

// IsUpgradeableConditionError returns true if error passed indicates that operator should report Upgradeable=False.
func IsUpgradeableConditionError(err error) bool {
	if err == nil {
		return false
	}
	if c, ok := err.(*conditionError); ok && strings.HasSuffix(c.condType, "Upgradeable") {
		return true
	}
	_, ok := err.(*notUpgradeableError)
	return ok
}

// conditionError contains all
type conditionError struct {
	condType string
	reason   string
	message  string
}

func (d *conditionError) Error() string {
	switch {
	case IsDegradedConditionError(d):
		return fmt.Sprintf("operator is degraded: %q (%s)", d.reason, d.message)
	case IsUpgradeableConditionError(d):
		return fmt.Sprintf("operator is not upgreadable: %q (%s)", d.reason, d.message)
	case IsAvailableConditionError(d):
		return fmt.Sprintf("operator is not available: %q (%s)", d.reason, d.message)
	}
	return fmt.Sprintf("operator unknown condition type: %q", d.condType)
}

func (d *conditionError) condition(status operatorv1.ConditionStatus) operatorv1.OperatorCondition {
	return operatorv1.OperatorCondition{
		Type:    d.condType,
		Status:  status,
		Reason:  d.reason,
		Message: d.message,
	}
}

func findConditionErrors(name string, err error) []operatorv1.OperatorCondition {
	foundConditions := []operatorv1.OperatorCondition{}
	switch e := err.(type) {
	case *degradedError:
		foundConditions = append(foundConditions, e.condition(operatorv1.ConditionTrue))
	case *unavailableError:
		foundConditions = append(foundConditions, e.condition(operatorv1.ConditionFalse))
	case *notUpgradeableError:
		foundConditions = append(foundConditions, e.condition(operatorv1.ConditionFalse))
	case errors.Aggregate:
		for _, err := range e.Errors() {
			foundConditions = append(foundConditions, findConditionErrors(name, err)...)
		}
	default:
		// if this condition already exists, append error messages.
		// this allows to aggregate multiple go errors together and report all of them inside single condition.
		existing := v1helpers.FindOperatorCondition(foundConditions, name+"Degraded")
		messages := []string{}
		if existing != nil {
			messages = []string{existing.Message}
		}
		messages = append(messages, err.Error())
		foundConditions = append(foundConditions, operatorv1.OperatorCondition{
			Type:    name + "Degraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "SyncError",
			Message: strings.Join(messages, ","),
		})
	}

	return foundConditions
}

// handleErrorConditions is used by reconcile() to report operator conditions based on the error.
func handleErrorConditions(client operatorv1helpers.OperatorClient, controllerName string, knownConditionsTypes sets.String, err error) error {
	allKnownConditions := sets.NewString(append([]string{controllerName + "Degraded"}, knownConditionsTypes.List()...)...)
	foundConditions := []operatorv1.OperatorCondition{}

	if err != nil {
		foundConditions = findConditionErrors(controllerName, err)
		// If we don't know about this condition type, then instead of setting it forever, error out.
		// Note: This is a programmer error, where the WithSyncErrorConditionTypes() have not listed the condition type used.
		for _, c := range foundConditions {
			if !allKnownConditions.Has(c.Type) {
				return fmt.Errorf("unknown condition type %+v requested (known: %#v)", c.Type, allKnownConditions.List())
			}
		}
	}

	updateConditionFuncs := []v1helpers.UpdateStatusFunc{}
	// clean up existing conditions first
	for _, conditionType := range allKnownConditions.List() {
		conditionDefaultStatus := operatorv1.ConditionTrue
		if strings.HasSuffix(conditionType, "Degraded") {
			conditionDefaultStatus = operatorv1.ConditionFalse
		}
		updatedCondition := operatorv1.OperatorCondition{
			Type:   conditionType,
			Status: conditionDefaultStatus,
			Reason: "AsExpected",
		}
		if condition := v1helpers.FindOperatorCondition(foundConditions, conditionType); condition != nil {
			updatedCondition = *condition
		}
		updateConditionFuncs = append(updateConditionFuncs, v1helpers.UpdateConditionFn(updatedCondition))
	}

	// update operator conditions
	if _, _, updateErr := v1helpers.UpdateStatus(client, updateConditionFuncs...); updateErr != nil {
		return updateErr
	}
	return err
}
