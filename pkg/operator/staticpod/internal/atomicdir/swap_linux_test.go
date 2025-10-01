//go:build linux

package atomicdir

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestSwap(t *testing.T) {
	stateFirst := directoryState{
		"1.txt": {
			Content: []byte("hello 1 world"),
			Perm:    0600,
		},
		"2.txt": {
			Content: []byte("hello 2 world"),
			Perm:    0400,
		},
	}
	stateSecond := directoryState{
		"a.txt": {
			Content: []byte("hello a world"),
			Perm:    0600,
		},
	}
	stateEmpty := directoryState{}

	expectNoError := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	}

	checkSuccess := func(t *testing.T, pathFirst string, stateFirst directoryState, pathSecond string, stateSecond directoryState, err error) {
		t.Helper()
		expectNoError(t, err)

		// Make sure the contents are swapped.
		stateFirst.CheckDirectoryMatches(t, pathSecond)
		stateSecond.CheckDirectoryMatches(t, pathFirst)
	}

	testCases := []struct {
		name        string
		setup       func(t *testing.T, tmpDir string) (pathFirst string, stateFirst directoryState, pathSecond string, stateSecond directoryState)
		checkResult func(t *testing.T, pathFirst string, stateFirst directoryState, pathSecond string, stateSecond directoryState, err error)
	}{
		{
			name: "success with absolute paths",
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateFirst.Write(t, pathFirst)
				stateSecond.Write(t, pathSecond)

				return pathFirst, stateFirst, pathSecond, stateSecond
			},
			checkResult: checkSuccess,
		},
		{
			name: "success with the first path relative",
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateFirst.Write(t, pathFirst)
				stateSecond.Write(t, pathSecond)

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
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateFirst.Write(t, pathFirst)
				stateSecond.Write(t, pathSecond)

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
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateFirst.Write(t, pathFirst)
				stateEmpty.Write(t, pathSecond)

				return pathFirst, stateFirst, pathSecond, stateEmpty
			},
			checkResult: checkSuccess,
		},
		{
			name: "success with both directories empty",
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				stateEmpty.Write(t, pathFirst)
				stateEmpty.Write(t, pathSecond)

				return pathFirst, stateEmpty, pathSecond, stateEmpty
			},
			checkResult: checkSuccess,
		},
		{
			name: "error with the first directory not existing",
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				expectNoError(t, os.Mkdir(pathSecond, 0755))

				return pathFirst, stateEmpty, pathSecond, stateEmpty
			},
			checkResult: func(t *testing.T, pathFirst string, stateFirst directoryState, pathSecond string, stateSecond directoryState, err error) {
				if !os.IsNotExist(err) {
					t.Errorf("Expected a directory not exists error, got %v", err)
				}
			},
		},
		{
			name: "error with the second directory not existing",
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				expectNoError(t, os.Mkdir(pathFirst, 0755))

				return pathFirst, stateEmpty, pathSecond, stateEmpty
			},
			checkResult: func(t *testing.T, pathFirst string, stateFirst directoryState, pathSecond string, stateSecond directoryState, err error) {
				if !os.IsNotExist(err) {
					t.Errorf("Expected a directory not exists error, got %v", err)
				}
			},
		},
		{
			name: "error with no directory existing",
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
				pathFirst := filepath.Join(tmpDir, "first")
				pathSecond := filepath.Join(tmpDir, "second")

				return pathFirst, stateEmpty, pathSecond, stateEmpty
			},
			checkResult: func(t *testing.T, pathFirst string, stateFirst directoryState, pathSecond string, stateSecond directoryState, err error) {
				if !os.IsNotExist(err) {
					t.Errorf("Expected a directory not exists error, got %v", err)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pathFirst, stateFirst, pathSecond, stateSecond := tc.setup(t, t.TempDir())
			tc.checkResult(t, pathFirst, stateFirst, pathSecond, stateSecond, swap(pathFirst, pathSecond))
		})
	}
}

type fileState struct {
	Content []byte
	Perm    os.FileMode
}

type directoryState map[string]fileState

func (dir directoryState) Write(t *testing.T, path string) {
	if err := os.MkdirAll(path, 0755); err != nil && !os.IsExist(err) {
		t.Fatalf("Failed to create directory %q: %v", path, err)
	}

	for filename, state := range dir {
		fullFilename := filepath.Join(path, filename)
		if err := os.WriteFile(fullFilename, state.Content, state.Perm); err != nil {
			t.Fatalf("Failed to write file %q: %v", fullFilename, err)
		}
	}
}

func (dir directoryState) CheckDirectoryMatches(t *testing.T, path string) {
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("Failed to read directory %q: %v", path, err)
	}

	expectedFiles := sets.KeySet(dir)
	for _, entry := range entries {
		// Mark the file as visited.
		expectedFiles.Delete(entry.Name())

		// Get the expected state.
		state, ok := dir[entry.Name()]
		if !ok {
			t.Errorf("Directory %q contains unexpected file %q", path, entry.Name())
			continue
		}

		// Check permissions.
		info, err := entry.Info()
		if err != nil {
			t.Errorf("Failed to stat file %q: %v", entry.Name(), err)
			continue
		}

		if info.Mode() != state.Perm {
			t.Errorf("Unexpected permissions on file %q: expected %v, got %v", entry.Name(), state.Perm, info.Mode())
		}

		// Check file content.
		content, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Errorf("Failed to read file %q: %v", entry.Name(), err)
			continue
		}
		if !bytes.Equal(state.Content, content) {
			t.Errorf("Unexpected content in file %q:\n%v", entry.Name(), cmp.Diff(string(state.Content), string(content)))
		}
	}
	if expectedFiles.Len() != 0 {
		t.Errorf("Some expected files were not found in directory %q: %s", path, expectedFiles.UnsortedList())
	}
}
