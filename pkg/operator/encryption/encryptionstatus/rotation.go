package encryptionstatus

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LatestCompletedRotationForKeyID returns the most recent completed entry for keyID.
// Rotations are stored newest-first.
func LatestCompletedRotationForKeyID(rotations []KMSPluginRotationStatus, keyID string) (KMSPluginRotationStatus, bool) {
	for _, rotation := range rotations {
		if rotation.KeyID != keyID {
			continue
		}
		if rotation.MigrationFinishTime != nil {
			return rotation, true
		}
	}
	return KMSPluginRotationStatus{}, false
}

// OpenRotation returns the in-progress rotation for keyID and kekID (no migrationFinishTime).
func OpenRotation(rotations []KMSPluginRotationStatus, keyID, kekID string) (KMSPluginRotationStatus, int, bool) {
	for i, rotation := range rotations {
		if rotation.KeyID != keyID || rotation.KEKID != kekID {
			continue
		}
		if rotation.MigrationFinishTime == nil {
			return rotation, i, true
		}
	}
	return KMSPluginRotationStatus{}, -1, false
}

// GetOrCreateOpenRotation ensures an open rotation entry exists for keyID and kekID with discoveryTime set.
func GetOrCreateOpenRotation(rotations []KMSPluginRotationStatus, keyID, kekID string, now metav1.Time) ([]KMSPluginRotationStatus, int) {
	if idx := indexRotation(rotations, keyID, kekID); idx >= 0 {
		if rotations[idx].MigrationFinishTime != nil {
			rotations = prependRotation(rotations, newOpenRotation(keyID, kekID, now))
			return rotations, 0
		}
		return SetDiscoveryTime(rotations, idx, now), idx
	}
	rotations = prependRotation(rotations, newOpenRotation(keyID, kekID, now))
	return rotations, 0
}

func newOpenRotation(keyID, kekID string, now metav1.Time) KMSPluginRotationStatus {
	discoveryTime := now.DeepCopy()
	return KMSPluginRotationStatus{
		KeyID:         keyID,
		KEKID:         kekID,
		DiscoveryTime: discoveryTime,
	}
}

// SetDiscoveryTime sets discoveryTime on the rotation at index when unset.
func SetDiscoveryTime(rotations []KMSPluginRotationStatus, index int, discoveryTime metav1.Time) []KMSPluginRotationStatus {
	if index < 0 || index >= len(rotations) {
		return rotations
	}
	if rotations[index].DiscoveryTime != nil {
		return rotations
	}
	rotations[index].DiscoveryTime = discoveryTime.DeepCopy()
	return rotations
}

// SetMigrationStartTime sets migrationStartTime on the rotation at index.
func SetMigrationStartTime(rotations []KMSPluginRotationStatus, index int, startTime metav1.Time) []KMSPluginRotationStatus {
	if index < 0 || index >= len(rotations) {
		return rotations
	}
	rotations[index].MigrationStartTime = startTime.DeepCopy()
	return rotations
}

// SetMigrationFinishTime sets migrationFinishTime on the rotation at index.
func SetMigrationFinishTime(rotations []KMSPluginRotationStatus, index int, finishTime metav1.Time) []KMSPluginRotationStatus {
	if index < 0 || index >= len(rotations) {
		return rotations
	}
	rotations[index].MigrationFinishTime = finishTime.DeepCopy()
	return rotations
}

func indexRotation(rotations []KMSPluginRotationStatus, keyID, kekID string) int {
	for i, rotation := range rotations {
		if rotation.KeyID == keyID && rotation.KEKID == kekID {
			return i
		}
	}
	return -1
}

func prependRotation(rotations []KMSPluginRotationStatus, rotation KMSPluginRotationStatus) []KMSPluginRotationStatus {
	rotations = append([]KMSPluginRotationStatus{rotation}, rotations...)
	if len(rotations) > MaxKeyRotationStatusEntries {
		rotations = rotations[:MaxKeyRotationStatusEntries]
	}
	return rotations
}
