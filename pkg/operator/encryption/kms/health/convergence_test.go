package health

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

func TestAllKeyIDsConverged(t *testing.T) {
	scenarios := []struct {
		name    string
		reports []operatorv1.KMSPluginHealthReport
		want    bool
	}{
		{name: "empty", want: true},
		{
			name: "single key unanimous",
			reports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "1", RemoteKeyID: "remote-a"},
				{KeyID: "1", RemoteKeyID: "remote-a"},
			},
			want: true,
		},
		{
			name: "single key split",
			reports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "1", RemoteKeyID: "remote-a"},
				{KeyID: "1", RemoteKeyID: "remote-b"},
			},
		},
		{
			name: "kms-to-kms migration different remotes per keyid",
			reports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "1", RemoteKeyID: "remote-old"},
				{KeyID: "1", RemoteKeyID: "remote-old"},
				{KeyID: "2", RemoteKeyID: "remote-new"},
				{KeyID: "2", RemoteKeyID: "remote-new"},
			},
			want: true,
		},
		{
			name: "one keyid group split during migration",
			reports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "1", RemoteKeyID: "remote-old"},
				{KeyID: "1", RemoteKeyID: "remote-old"},
				{KeyID: "2", RemoteKeyID: "remote-new"},
				{KeyID: "2", RemoteKeyID: "remote-other"},
			},
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			if got := AllKeyIDsConverged(scenario.reports); got != scenario.want {
				t.Fatalf("got %v want %v", got, scenario.want)
			}
		})
	}
}

func TestPruneStaleReports(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	ttl := 10 * time.Minute
	fresh := operatorv1.KMSPluginHealthReport{
		NodeName:        "node-a",
		KeyID:           "1",
		RemoteKeyID:     "remote-a",
		LastCheckedTime: metav1.NewTime(now.Add(-5 * time.Minute)),
	}
	stale := operatorv1.KMSPluginHealthReport{
		NodeName:        "node-b",
		KeyID:           "1",
		RemoteKeyID:     "remote-a",
		LastCheckedTime: metav1.NewTime(now.Add(-10 * time.Minute)),
	}
	kept := PruneStaleReports([]operatorv1.KMSPluginHealthReport{fresh, stale}, now, ttl)
	if len(kept) != 1 || kept[0].NodeName != "node-a" {
		t.Fatalf("got %#v, want only fresh node-a", kept)
	}
}
