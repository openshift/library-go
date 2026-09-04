package health

import (
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
)

func TestConvergedRemoteKeyID(t *testing.T) {
	scenarios := []struct {
		name            string
		reports         []operatorv1.KMSPluginHealthReport
		wantConverged   bool
		wantRemoteKeyID string
	}{
		{
			name: "unanimous",
			reports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "3", RemoteKeyID: "remote-a"},
				{KeyID: "3", RemoteKeyID: "remote-a"},
			},
			wantConverged:   true,
			wantRemoteKeyID: "remote-a",
		},
		{
			name: "split brain",
			reports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "3", RemoteKeyID: "remote-a"},
				{KeyID: "3", RemoteKeyID: "remote-b"},
			},
		},
		{
			name: "empty",
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			got := ConvergedRemoteKeyID(scenario.reports)
			if got.Converged != scenario.wantConverged || got.RemoteKeyID != scenario.wantRemoteKeyID {
				t.Fatalf("got %#v want converged=%v remoteKeyID=%q", got, scenario.wantConverged, scenario.wantRemoteKeyID)
			}
		})
	}
}

func TestReportsForKeyID(t *testing.T) {
	reports := []operatorv1.KMSPluginHealthReport{
		{KeyID: "3", RemoteKeyID: "a"},
		{KeyID: "2", RemoteKeyID: "b"},
		{KeyID: "3", RemoteKeyID: "a"},
	}
	filtered := ReportsForKeyID(reports, "3")
	if len(filtered) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(filtered))
	}
}
