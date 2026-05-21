package encryptionstatus

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPrependRotationMaxEntries(t *testing.T) {
	rotations := make([]KMSPluginRotationStatus, MaxKeyRotationStatusEntries)
	for i := range rotations {
		rotations[i] = KMSPluginRotationStatus{KEKID: string(rune('a' + i))}
	}
	rotations = prependRotation(rotations, KMSPluginRotationStatus{KeyID: "1", KEKID: "new"})
	if len(rotations) != MaxKeyRotationStatusEntries {
		t.Fatalf("expected %d entries, got %d", MaxKeyRotationStatusEntries, len(rotations))
	}
	if rotations[0].KEKID != "new" {
		t.Fatalf("expected newest entry first, got %q", rotations[0].KEKID)
	}
}

func TestUpsertOpenRotationUsesProvidedNowForMissingDiscoveryTime(t *testing.T) {
	fixed := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	now := metav1.NewTime(fixed)
	rotations := []KMSPluginRotationStatus{
		{KeyID: "1", KEKID: "kek-a"},
	}

	updated, idx := GetOrCreateOpenRotation(rotations, "1", "kek-a", now)
	if idx != 0 {
		t.Fatalf("expected index 0, got %d", idx)
	}
	if updated[0].DiscoveryTime == nil || !updated[0].DiscoveryTime.Equal(&now) {
		t.Fatalf("expected discoveryTime %v, got %v", now, updated[0].DiscoveryTime)
	}
	if updated[0].KeyID != "1" || updated[0].KEKID != "kek-a" {
		t.Fatalf("unexpected entry identity: %+v", updated[0])
	}
}

func TestLatestCompletedRotationForKeyID(t *testing.T) {
	finish := metav1.Now()
	rotations := []KMSPluginRotationStatus{
		{KeyID: "1", KEKID: "open"},
		{KeyID: "1", KEKID: "new", MigrationFinishTime: &finish},
		{KeyID: "1", KEKID: "old", MigrationFinishTime: &finish},
		{KeyID: "2", KEKID: "other", MigrationFinishTime: &finish},
	}
	latest, ok := LatestCompletedRotationForKeyID(rotations, "1")
	if !ok || latest.KEKID != "new" {
		t.Fatalf("expected first completed entry for key 1, got %q ok=%v", latest.KEKID, ok)
	}
}
