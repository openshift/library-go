package staticpod

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSwapDirectoriesAtomic(t *testing.T) {
	expectNoError := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	}

	testCases := []struct {
		name        string
		setup       func(t *testing.T, tmpDir string) (dirA, dirB string)
		checkResult func(t *testing.T, dirA, dirB string, err error)
	}{
		{
			name: "both directories exist",
			setup: func(t *testing.T, tmpDir string) (string, string) {
				dirA := filepath.Join(tmpDir, "a")
				dirB := filepath.Join(tmpDir, "b")

				if err := os.Mkdir(dirA, 0755); err != nil {
					t.Fatalf("Failed to create directory %q: %v", dirA, err)
				}
				if err := os.Mkdir(dirB, 0755); err != nil {
					t.Fatalf("Failed to create directory %q: %v", dirB, err)
				}

				fileA, err := os.Create(filepath.Join(dirA, "1.txt"))
				expectNoError(t, err)
				defer fileA.Close()

				fileB, err := os.Create(filepath.Join(dirB, "2.txt"))
				expectNoError(t, err)
				defer fileB.Close()

				return dirA, dirB
			},
			checkResult: func(t *testing.T, dirA, dirB string, err error) {
				expectNoError(t, err)

				// Make sure the contents are swapped.
				fileA, err := os.Open(filepath.Join(dirA, "2.txt"))
				if err != nil {
					t.Errorf("Expected directory %q to contain file 2.txt: %v", dirA, err)
				}
				defer fileA.Close()

				fileB, err := os.Open(filepath.Join(dirB, "1.txt"))
				if err != nil {
					t.Errorf("Expected directory %q to contain file 1.txt: %v", dirB, err)
				}
				defer fileB.Close()
			},
		},
		{
			name: "directory A does not exist",
			setup: func(t *testing.T, tmpDir string) (string, string) {
				dirA := filepath.Join(tmpDir, "a")
				dirB := filepath.Join(tmpDir, "b")

				if err := os.Mkdir(dirB, 0755); err != nil {
					t.Fatalf("Failed to create directory %q: %v", dirB, err)
				}

				return dirA, dirB
			},
			checkResult: func(t *testing.T, dirA, dirB string, err error) {
				if !os.IsNotExist(err) {
					t.Errorf("Expected a directory not exists error, got %v", err)
				}
			},
		},
		{
			name: "directory B does not exist",
			setup: func(t *testing.T, tmpDir string) (string, string) {
				dirA := filepath.Join(tmpDir, "a")
				dirB := filepath.Join(tmpDir, "b")

				if err := os.Mkdir(dirA, 0755); err != nil {
					t.Fatalf("Failed to create directory %q: %v", dirA, err)
				}

				return dirA, dirB
			},
			checkResult: func(t *testing.T, dirA, dirB string, err error) {
				if !os.IsNotExist(err) {
					t.Errorf("Expected a directory not exists error, got %v", err)
				}
			},
		},
		{
			name: "directory A not an absolute path",
			setup: func(t *testing.T, tmpDir string) (string, string) {
				dirA := "a"
				dirB := filepath.Join(tmpDir, "b")
				return dirA, dirB
			},
			checkResult: func(t *testing.T, dirA, dirB string, err error) {
				if err == nil || err.Error() != `not an absolute path: "a"` {
					t.Errorf("Expected not an absolute path error, got %v", err)
				}
			},
		},
		{
			name: "directory B not an absolute path",
			setup: func(t *testing.T, tmpDir string) (string, string) {
				dirA := filepath.Join(tmpDir, "a")
				dirB := "b"
				return dirA, dirB
			},
			checkResult: func(t *testing.T, dirA, dirB string, err error) {
				if err == nil || err.Error() != `not an absolute path: "b"` {
					t.Errorf("Expected not an absolute path error, got %v", err)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dirA, dirB := tc.setup(t, t.TempDir())
			tc.checkResult(t, dirA, dirB, SwapDirectoriesAtomic(dirA, dirB))
		})
	}
}
