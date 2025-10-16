//go:build linux

package atomicdir

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
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
		stateFirst.CheckDirectoryMatches(t, pathSecond, 0755)
		stateSecond.CheckDirectoryMatches(t, pathFirst, 0755)
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

				stateFirst.Write(t, pathFirst, 0755)
				stateSecond.Write(t, pathSecond, 0755)

				return pathFirst, stateFirst, pathSecond, stateSecond
			},
			checkResult: checkSuccess,
		},
		{
			name: "success with the first path relative",
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
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
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
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
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
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
			setup: func(t *testing.T, tmpDir string) (string, directoryState, string, directoryState) {
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

type directoryState map[string]File

func (dir directoryState) Write(tb testing.TB, dirPath string, dirPerm os.FileMode) {
	if err := os.MkdirAll(dirPath, dirPerm); err != nil {
		tb.Fatalf("Failed to create directory %q: %v", dirPath, err)
	}

	for filename, state := range dir {
		fullFilename := filepath.Join(dirPath, filename)
		if err := os.WriteFile(fullFilename, state.Content, state.Perm); err != nil {
			tb.Fatalf("Failed to write file %q: %v", fullFilename, err)
		}
	}
}

func (dir directoryState) CheckDirectoryMatches(tb testing.TB, dirPath string, dirPerm os.FileMode) {
	// Ensure the directory permissions match.
	stat, err := os.Stat(dirPath)
	if err != nil {
		tb.Fatalf("Failed to stat %q: %v", dirPath, err)
	}
	if perm := stat.Mode().Perm(); perm != dirPerm {
		tb.Errorf("Permissions mismatch detected for %q: expected %v, got %v", dirPath, dirPerm, perm)
	}

	// Ensure all files are in sync.
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		tb.Fatalf("Failed to read directory %q: %v", dirPath, err)
	}

	actualState := make(directoryState, len(entries))
	for _, entry := range entries {
		filePath := filepath.Join(dirPath, entry.Name())

		info, err := entry.Info()
		if err != nil {
			tb.Fatalf("Failed to stat %q: %v", filePath, err)
		}

		if info.IsDir() {
			tb.Errorf("Unexpected directory detected: %q", filePath)
			continue
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			tb.Fatalf("Failed to read %q: %v", filePath, err)
		}

		actualState[entry.Name()] = File{
			Content: content,
			Perm:    info.Mode(),
		}
	}
	if !cmp.Equal(dir, actualState) {
		tb.Errorf("Unexpected directory content for %q:\n%s\n", dirPath, cmp.Diff(dir, actualState))
	}
}
