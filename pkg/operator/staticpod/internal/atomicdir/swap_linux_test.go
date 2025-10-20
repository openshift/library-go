//go:build linux

package atomicdir

import (
	"os"
	"path/filepath"
	"testing"

	adtesting "github.com/openshift/library-go/pkg/operator/staticpod/internal/atomicdir/testing"
)

func TestSwap(t *testing.T) {
	stateFirst := adtesting.DirectoryState{
		"1.txt": {
			Content: []byte("hello 1 world"),
			Perm:    0600,
		},
		"2.txt": {
			Content: []byte("hello 2 world"),
			Perm:    0400,
		},
	}
	stateSecond := adtesting.DirectoryState{
		"a.txt": {
			Content: []byte("hello a world"),
			Perm:    0600,
		},
	}
	stateEmpty := adtesting.DirectoryState{}

	expectNoError := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	}

	checkSuccess := func(t *testing.T, pathFirst string, stateFirst adtesting.DirectoryState, pathSecond string, stateSecond adtesting.DirectoryState, err error) {
		t.Helper()
		expectNoError(t, err)

		// Make sure the contents are swapped.
		stateFirst.CheckDirectoryMatches(t, pathSecond, 0755)
		stateSecond.CheckDirectoryMatches(t, pathFirst, 0755)
	}

	testCases := []struct {
		name        string
		setup       func(t *testing.T, tmpDir string) (pathFirst string, stateFirst adtesting.DirectoryState, pathSecond string, stateSecond adtesting.DirectoryState)
		checkResult func(t *testing.T, pathFirst string, stateFirst adtesting.DirectoryState, pathSecond string, stateSecond adtesting.DirectoryState, err error)
	}{
		{
			name: "success with absolute paths",
			setup: func(t *testing.T, tmpDir string) (string, adtesting.DirectoryState, string, adtesting.DirectoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateFirst.Write(t, pathFirst, 0755)
				stateSecond.Write(t, pathSecond, 0755)

				return pathFirst, stateFirst, pathSecond, stateSecond
			},
			checkResult: checkSuccess,
		},
		{
			name: "success with the first path relative",
			setup: func(t *testing.T, tmpDir string) (string, adtesting.DirectoryState, string, adtesting.DirectoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateFirst.Write(t, pathFirst, 0755)
				stateSecond.Write(t, pathSecond, 0755)

				cwd, err := os.Getwd()
				expectNoError(t, err)

				relFirst, err := filepath.Rel(cwd, pathFirst)
				expectNoError(t, err)

				return relFirst, stateFirst, pathSecond, stateSecond
			},
			checkResult: checkSuccess,
		},
		{
			name: "success with the second path relative",
			setup: func(t *testing.T, tmpDir string) (string, adtesting.DirectoryState, string, adtesting.DirectoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateFirst.Write(t, pathFirst, 0755)
				stateSecond.Write(t, pathSecond, 0755)

				cwd, err := os.Getwd()
				expectNoError(t, err)

				relSecond, err := filepath.Rel(cwd, pathSecond)
				expectNoError(t, err)

				return pathFirst, stateFirst, relSecond, stateSecond
			},
			checkResult: checkSuccess,
		},
		{
			name: "success with an empty directory",
			setup: func(t *testing.T, tmpDir string) (string, adtesting.DirectoryState, string, adtesting.DirectoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateFirst.Write(t, pathFirst, 0755)
				stateEmpty.Write(t, pathSecond, 0755)

				return pathFirst, stateFirst, pathSecond, stateEmpty
			},
			checkResult: checkSuccess,
		},
		{
			name: "success with both directories empty",
			setup: func(t *testing.T, tmpDir string) (string, adtesting.DirectoryState, string, adtesting.DirectoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateEmpty.Write(t, pathFirst, 0755)
				stateEmpty.Write(t, pathSecond, 0755)

				return pathFirst, stateEmpty, pathSecond, stateEmpty
			},
			checkResult: checkSuccess,
		},
		{
			name: "error with the first directory not existing",
			setup: func(t *testing.T, tmpDir string) (string, adtesting.DirectoryState, string, adtesting.DirectoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				expectNoError(t, os.Mkdir(pathSecond, 0755))

				return pathFirst, stateEmpty, pathSecond, stateEmpty
			},
			checkResult: func(t *testing.T, pathFirst string, stateFirst adtesting.DirectoryState, pathSecond string, stateSecond adtesting.DirectoryState, err error) {
				if !os.IsNotExist(err) {
					t.Errorf("Expected a directory not exists error, got %v", err)
				}
			},
		},
		{
			name: "error with the second directory not existing",
			setup: func(t *testing.T, tmpDir string) (string, adtesting.DirectoryState, string, adtesting.DirectoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				expectNoError(t, os.Mkdir(pathFirst, 0755))

				return pathFirst, stateEmpty, pathSecond, stateEmpty
			},
			checkResult: func(t *testing.T, pathFirst string, stateFirst adtesting.DirectoryState, pathSecond string, stateSecond adtesting.DirectoryState, err error) {
				if !os.IsNotExist(err) {
					t.Errorf("Expected a directory not exists error, got %v", err)
				}
			},
		},
		{
			name: "error with no directory existing",
			setup: func(t *testing.T, tmpDir string) (string, adtesting.DirectoryState, string, adtesting.DirectoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				return pathFirst, stateEmpty, pathSecond, stateEmpty
			},
			checkResult: func(t *testing.T, pathFirst string, stateFirst adtesting.DirectoryState, pathSecond string, stateSecond adtesting.DirectoryState, err error) {
				if !os.IsNotExist(err) {
					t.Errorf("Expected a directory not exists error, got %v", err)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pathFirst, stateFirst, pathSecond, stateSecond := tc.setup(t, t.TempDir())
			tc.checkResult(t, pathFirst, stateFirst, pathSecond, stateSecond, swap(pathFirst, pathSecond))
		})
	}
}
