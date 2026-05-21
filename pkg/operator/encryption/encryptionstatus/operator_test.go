package encryptionstatus

import (
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
)

func TestHealthReportsFromConditions(t *testing.T) {
	status := &operatorv1.OperatorStatus{
		Conditions: []operatorv1.OperatorCondition{
			{
				Type:    KMSHealthReporterConditionPrefix + "master-0",
				Message: `[{"kekID":"kek-1","keyID":"2","status":"healthy","lastChecked":"2026-05-08T12:34:56Z"}]`,
			},
		},
	}
	reports := HealthReportsFromOperatorStatus(status)
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}
	if reports[0].NodeName != "master-0" || reports[0].KeyID != "2" || reports[0].KEKID != "kek-1" {
		t.Fatalf("unexpected report: %+v", reports[0])
	}
}

func TestKeyRotationStatusRoundTrip(t *testing.T) {
	rotations := []KMSPluginRotationStatus{{KeyID: "1", KEKID: "kek-a"}}
	update := SetKeyRotationStatusCondition(rotations)
	status := &operatorv1.OperatorStatus{}
	if err := update(status); err != nil {
		t.Fatal(err)
	}
	got, err := KeyRotationStatusFromOperatorStatus(status)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].KeyID != "1" || got[0].KEKID != "kek-a" {
		t.Fatalf("unexpected rotations: %+v", got)
	}
}
