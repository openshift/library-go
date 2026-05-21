package encryptionstatus

import (
	"encoding/json"
	"fmt"
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"
)

// interimHealthReport is the JSON shape published in KMSHealthReporter_* condition messages.
type interimHealthReport struct {
	KEKID       string `json:"kekID"`
	KeyID       string `json:"keyID"`
	Status      string `json:"status"`
	LastChecked string `json:"lastChecked"`
}

// encryptionStatusFromOperator reads structured encryption status from operator status.
// Interim conditions remain the source until operator API types expose EncryptionStatus.
func encryptionStatusFromOperator(status *operatorv1.OperatorStatus) APIServerEncryptionStatus {
	_ = status
	return APIServerEncryptionStatus{}
}

// HealthReportsFromOperatorStatus returns health reports from structured status when present,
// otherwise parses interim KMSHealthReporter_* operator conditions.
func HealthReportsFromOperatorStatus(status *operatorv1.OperatorStatus) []KMSPluginHealthReport {
	encryptionStatus := encryptionStatusFromOperator(status)
	if len(encryptionStatus.HealthReports) > 0 {
		return encryptionStatus.HealthReports
	}
	return healthReportsFromConditions(status)
}

func healthReportsFromConditions(status *operatorv1.OperatorStatus) []KMSPluginHealthReport {
	if status == nil {
		return nil
	}

	var reports []KMSPluginHealthReport
	for _, condition := range status.Conditions {
		if !strings.HasPrefix(condition.Type, KMSHealthReporterConditionPrefix) {
			continue
		}
		nodeName := strings.TrimPrefix(condition.Type, KMSHealthReporterConditionPrefix)
		parsed, err := parseInterimHealthMessage(condition.Message)
		if err != nil {
			continue
		}
		for _, entry := range parsed {
			reports = append(reports, KMSPluginHealthReport{
				KeyID:    entry.KeyID,
				NodeName: nodeName,
				KEKID:    entry.KEKID,
				Status:   entry.Status,
				// LastChecked left zero when only interim JSON timestamp is available without parsing.
			})
		}
	}
	return reports
}

func parseInterimHealthMessage(message string) ([]interimHealthReport, error) {
	if len(message) == 0 {
		return nil, nil
	}
	var parsed []interimHealthReport
	if err := json.Unmarshal([]byte(message), &parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

// KeyRotationStatusFromOperatorStatus reads rotation history from structured status when present,
// otherwise from the interim EncryptionKeyRotationStatus condition.
func KeyRotationStatusFromOperatorStatus(status *operatorv1.OperatorStatus) ([]KMSPluginRotationStatus, error) {
	encryptionStatus := encryptionStatusFromOperator(status)
	if len(encryptionStatus.KeyRotationStatus) > 0 {
		return encryptionStatus.KeyRotationStatus, nil
	}
	return keyRotationStatusFromCondition(status)
}

func keyRotationStatusFromCondition(status *operatorv1.OperatorStatus) ([]KMSPluginRotationStatus, error) {
	if status == nil {
		return nil, nil
	}
	for _, condition := range status.Conditions {
		if condition.Type != KeyRotationStatusConditionType {
			continue
		}
		if len(condition.Message) == 0 {
			return nil, nil
		}
		var rotations []KMSPluginRotationStatus
		if err := json.Unmarshal([]byte(condition.Message), &rotations); err != nil {
			return nil, fmt.Errorf("failed to parse %s condition: %w", KeyRotationStatusConditionType, err)
		}
		return rotations, nil
	}
	return nil, nil
}

// SetKeyRotationStatusCondition returns an update func that stores keyRotationStatus in operator conditions
// until status.encryptionStatus is available on the operator API type.
func SetKeyRotationStatusCondition(rotations []KMSPluginRotationStatus) func(*operatorv1.OperatorStatus) error {
	return func(status *operatorv1.OperatorStatus) error {
		if status == nil {
			return fmt.Errorf("operator status is nil")
		}
		message := ""
		if len(rotations) > 0 {
			bs, err := json.Marshal(rotations)
			if err != nil {
				return err
			}
			message = string(bs)
		}
		condition := operatorv1.OperatorCondition{
			Type:    KeyRotationStatusConditionType,
			Status:  operatorv1.ConditionTrue,
			Reason:  KeyRotationStatusConditionReason,
			Message: message,
		}
		setOperatorCondition(&status.Conditions, condition)
		return nil
	}
}

func setOperatorCondition(conditions *[]operatorv1.OperatorCondition, newCondition operatorv1.OperatorCondition) {
	if conditions == nil {
		return
	}
	for i, existing := range *conditions {
		if existing.Type == newCondition.Type {
			(*conditions)[i] = newCondition
			return
		}
	}
	*conditions = append(*conditions, newCondition)
}
