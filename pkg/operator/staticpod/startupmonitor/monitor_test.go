package startupmonitor

import (
	"testing"
)

func TestLoadTargetManifestAndExtractRevision(t *testing.T) {
	scenarios := []struct {
		name             string
		goldenFilePrefix string
		expectedRev      int
		expectError      bool
	}{

		// scenario 1
		{
			name:             "happy path: a revision is extracted",
			goldenFilePrefix: "scenario-1",
			expectedRev:      8,
		},

		// scenario 2
		{
			name:             "the target pod doesn't have a revision label",
			goldenFilePrefix: "scenario-2",
			expectError:      true,
		},

		// scenario 3
		{
			name:             "the target pod has an incorrect label",
			goldenFilePrefix: "scenario-3",
			expectError:      true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// test data
			target := newMonitor(nil)
			target.manifestsPath = "./testdata"
			target.targetName = scenario.goldenFilePrefix

			// act
			rev, err := target.loadRootTargetPodAndExtractRevision()

			// validate
			if err != nil && !scenario.expectError {
				t.Fatal(err)
			}
			if err == nil && scenario.expectError {
				t.Fatal("expected to get an error")
			}
			if rev != scenario.expectedRev {
				t.Errorf("unexpected rev %d, expected %d", rev, scenario.expectedRev)
			}
		})
	}
}

func validateError(t *testing.T, actualErr error, expectedErr string) {
	if actualErr != nil && len(expectedErr) == 0 {
		t.Fatalf("unexpected error: %v", actualErr)
	}
	if actualErr == nil && len(expectedErr) > 0 {
		t.Fatal("expected to get an error")
	}
	if actualErr != nil && actualErr.Error() != expectedErr {
		t.Fatalf("incorrect error: %v, expected: %v", actualErr, expectedErr)
	}
}
