package encryptionstatus

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// APIServerEncryptionStatus mirrors the future operator/config status field for KMS encryption.
type APIServerEncryptionStatus struct {
	HealthReports     []KMSPluginHealthReport   `json:"healthReports,omitempty"`
	KeyRotationStatus []KMSPluginRotationStatus `json:"keyRotationStatus,omitempty"`
}

// KMSPluginHealthReport describes per-node KMS plugin health (filled by the health controller).
type KMSPluginHealthReport struct {
	KeyID       string      `json:"keyId"`
	NodeName    string      `json:"nodeName"`
	KEKID       string      `json:"kekId,omitempty"`
	Status      string      `json:"status"`
	LastChecked metav1.Time `json:"lastChecked"`
	Detail      string      `json:"detail,omitempty"`
}

// KMSPluginRotationStatus tracks one KEK rotation episode on the operand operator.
type KMSPluginRotationStatus struct {
	KeyID               string       `json:"keyId"`
	KEKID               string       `json:"kekId"`
	DiscoveryTime       *metav1.Time `json:"discoveryTime,omitempty"`
	MigrationStartTime  *metav1.Time `json:"migrationStartTime,omitempty"`
	MigrationFinishTime *metav1.Time `json:"migrationFinishTime,omitempty"`
}

const (
	// MaxKeyRotationStatusEntries is the maximum number of rotation history entries kept in status.
	MaxKeyRotationStatusEntries = 10

	// KMSHealthReporterConditionPrefix is the interim condition type prefix used by the health controller.
	KMSHealthReporterConditionPrefix = "KMSHealthReporter_"

	// KeyRotationStatusConditionType stores keyRotationStatus JSON until status.encryptionStatus is available on the operator API.
	KeyRotationStatusConditionType = "EncryptionKeyRotationStatus"

	// KeyRotationStatusConditionReason is set when the condition carries the current rotation status snapshot.
	KeyRotationStatusConditionReason = "AsExpected"
)
