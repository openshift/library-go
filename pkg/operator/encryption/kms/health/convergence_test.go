package health

import (
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
)

func TestConvergedRemoteKeyID(t *testing.T) {
	scenarios := []struct {
		name            string
		reports         []operatorv1.KMSPluginHealthReport
		wantRemoteKeyID string
	}{
		{
			name: "unanimous",
			reports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "3", RemoteKeyID: "remote-a"},
				{KeyID: "3", RemoteKeyID: "remote-a"},
			},
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
		{
			name: "empty remote key id",
			reports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "3", RemoteKeyID: ""},
				{KeyID: "3", RemoteKeyID: ""},
			},
		},
		{
			name: "mixed empty remote key id",
			reports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "3", RemoteKeyID: "remote-a"},
				{KeyID: "3", RemoteKeyID: ""},
			},
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			got := ConvergedRemoteKeyID(scenario.reports)
			if got != scenario.wantRemoteKeyID {
				t.Fatalf("got %q want %q", got, scenario.wantRemoteKeyID)
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
	want := []operatorv1.KMSPluginHealthReport{
		{KeyID: "3", RemoteKeyID: "a"},
		{KeyID: "3", RemoteKeyID: "a"},
	}
	filtered := ReportsForKeyID(reports, "3")
	if len(filtered) != len(want) {
		t.Fatalf("expected %d reports, got %d", len(want), len(filtered))
	}
	for i, report := range filtered {
		if report.KeyID != want[i].KeyID || report.RemoteKeyID != want[i].RemoteKeyID {
			t.Fatalf("filtered[%d] = %#v, want %#v", i, report, want[i])
		}
	}
}
