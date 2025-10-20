package testing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/openshift/library-go/pkg/operator/staticpod/internal/atomicdir/types"
)

// DirectoryState can be used both bootstrap and check a directory state.
type DirectoryState map[string]types.File

// Write writes the given state into the given directory.
func (dir DirectoryState) Write(tb testing.TB, dirPath string, dirPerm os.FileMode) {
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

// CheckDirectoryMatches checks the given directory against the given state.
func (dir DirectoryState) CheckDirectoryMatches(tb testing.TB, dirPath string, dirPerm os.FileMode) {
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

	actualState := make(DirectoryState, len(entries))
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

		actualState[entry.Name()] = types.File{
			Content: content,
			Perm:    info.Mode(),
		}
	}
	if !cmp.Equal(dir, actualState) {
		tb.Errorf("Unexpected directory content for %q:\n%s\n", dirPath, cmp.Diff(dir, actualState))
	}
}
