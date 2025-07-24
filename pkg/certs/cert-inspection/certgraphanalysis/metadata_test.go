package certgraphanalysis

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestDurationToHumanReadableString(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{0, "0s"},
		{time.Second, "1s"},
		{2 * time.Second, "2s"},
		{time.Minute, "1m"},
		{time.Minute + 30*time.Second, "1m30s"},
		{time.Hour, "1h"},
		{25 * time.Hour, "1d1h"},
		{30 * 24 * time.Hour, "1mo"},
		{365 * 24 * time.Hour, "1y"},
		{400 * 24 * time.Hour, "1y1mo5d"},
		{-time.Minute, "1m"},               // negative duration
		{-400 * 24 * time.Hour, "1y1mo5d"}, // negative composite
		{3*time.Minute + 4*time.Second, "3m4s"},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			result := durationToHumanReadableString(test.duration)
			if result != test.expected {
				t.Errorf("expected %s, got %s", test.expected, result)
			}
		})
	}
}

func TestHumanizeRefreshPeriodFromMetadata(t *testing.T) {
	tests := []struct {
		metadata string
		expected string
	}{
		{
			metadata: "72h00m00s",
			expected: "3d",
		},
		{
			metadata: "124h25m00s",
			expected: "5d4h25m",
		},
		{
			metadata: "82080h00m00s",
			expected: "9y4mo15d",
		},
	}
	for _, test := range tests {
		t.Run(test.metadata, func(t *testing.T) {
			result := map[string]string{
				"certificates.openshift.io/refresh-period": test.metadata,
			}
			humanizeRefreshPeriodFromMetadata(result)

			expected := map[string]string{
				"certificates.openshift.io/refresh-period":              test.expected,
				"rewritten.cert-info.openshift.io/RewriteRefreshPeriod": test.metadata,
			}
			diff := cmp.Diff(expected, result)
			if diff != "" {
				t.Errorf("expected %v, got %v, diff: %s", test.expected, result, diff)
			}
		})
	}
}

func TestHumanizeRefreshPeriodFromMetadataNils(t *testing.T) {
	humanizeRefreshPeriodFromMetadata(nil)
	humanizeRefreshPeriodFromMetadata(map[string]string{})
}
