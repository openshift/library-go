package health

import (
	"testing"

	operatorv1 "github.com/openshift/api/operator/v1"
)

func TestConvergedRemoteKeyID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		reports []operatorv1.KMSPluginHealthReport
		want    ConvergenceResult
	}{
		{
			name:    "empty reports",
			reports: nil,
			want:    ConvergenceResult{},
		},
		{
			name: "single report",
			reports: []operatorv1.KMSPluginHealthReport{
				{NodeName: "node-a", KeyID: "1", RemoteKeyID: "kek-abc"},
			},
			want: ConvergenceResult{
				Converged:   true,
				RemoteKeyID: "kek-abc",
			},
		},
		{
			name: "unanimous match across nodes",
			reports: []operatorv1.KMSPluginHealthReport{
				{NodeName: "node-a", KeyID: "1", RemoteKeyID: "kek-abc"},
				{NodeName: "node-b", KeyID: "1", RemoteKeyID: "kek-abc"},
				{NodeName: "node-c", KeyID: "1", RemoteKeyID: "kek-abc"},
			},
			want: ConvergenceResult{
				Converged:   true,
				RemoteKeyID: "kek-abc",
			},
		},
		{
			name: "split-brain across nodes",
			reports: []operatorv1.KMSPluginHealthReport{
				{NodeName: "node-a", KeyID: "1", RemoteKeyID: "kek-old"},
				{NodeName: "node-b", KeyID: "1", RemoteKeyID: "kek-new"},
			},
			want: ConvergenceResult{},
		},
		{
			name: "single report empty remote key ID",
			reports: []operatorv1.KMSPluginHealthReport{
				{NodeName: "node-a", KeyID: "1", RemoteKeyID: ""},
			},
			want: ConvergenceResult{},
		},
		{
			name: "unanimous empty remote key ID",
			reports: []operatorv1.KMSPluginHealthReport{
				{NodeName: "node-a", KeyID: "1", RemoteKeyID: ""},
				{NodeName: "node-b", KeyID: "1", RemoteKeyID: ""},
			},
			want: ConvergenceResult{},
		},
		{
			name: "mixed empty and non-empty remote key ID",
			reports: []operatorv1.KMSPluginHealthReport{
				{NodeName: "node-a", KeyID: "1", RemoteKeyID: ""},
				{NodeName: "node-b", KeyID: "1", RemoteKeyID: "kek-abc"},
			},
			want: ConvergenceResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvergedRemoteKeyID(tt.reports)
			if got != tt.want {
				t.Fatalf("ConvergedRemoteKeyID() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
