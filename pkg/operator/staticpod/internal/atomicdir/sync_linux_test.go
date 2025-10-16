//go:build linux

package atomicdir

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	adtesting "github.com/openshift/library-go/pkg/operator/staticpod/internal/atomicdir/testing"
	"github.com/openshift/library-go/pkg/operator/staticpod/internal/atomicdir/types"
)

func TestSync(t *testing.T) {
	newRealFS := func() *fileSystem {
		fs := realFS
		return &fs
	}

	type testCase struct {
		name string
		// newFS is the main mocking factory for the test run.
		newFS func() *fileSystem
		// existingFiles is used to populate the target directory state before testing.
		// An empty map will cause the directory to be created, a nil map will cause no directory to be created.
		existingFiles map[string]types.File
		// filesToSync will be synchronized into the target directory.
		filesToSync map[string]types.File
		// expectedFiles contains the files that are expected to be in the target directory after sync is called.
		expectedFiles map[string]types.File
		// expectSyncError check the return value from Sync.
		expectSyncError bool
		// expectLingeringStagingDirectory can be set to true to expect the temporary directory not to be removed.
		expectLingeringStagingDirectory bool
	}

	errorTestCase := func(name string, newFS func() *fileSystem) testCase {
		return testCase{
			name:  name,
			newFS: newFS,
			existingFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"api.crt": {Content: []byte("rotated TLS cert"), Perm: 0600},
				"api.key": {Content: []byte("rotated TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			expectSyncError: true,
		}
	}

	testCases := []testCase{
		{
			name:          "target directory does not exist",
			newFS:         newRealFS,
			existingFiles: nil,
			filesToSync: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
		},
		{
			name:          "target directory is empty",
			newFS:         newRealFS,
			existingFiles: map[string]types.File{},
			filesToSync: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
		},
		{
			name:  "target directory already synchronized",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
		},
		{
			name:  "change file contents preserving the filenames",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"tls.crt": {Content: []byte("rotated TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("rotated TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"tls.crt": {Content: []byte("rotated TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("rotated TLS key"), Perm: 0600},
			},
		},
		{
			name:  "change filenames preserving the file contents",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"api.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"api.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"api.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"api.key": {Content: []byte("TLS key"), Perm: 0600},
			},
		},
		{
			name:  "change filenames and file contents",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"api.crt": {Content: []byte("rotated TLS cert"), Perm: 0600},
				"api.key": {Content: []byte("rotated TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"api.crt": {Content: []byte("rotated TLS cert"), Perm: 0600},
				"api.key": {Content: []byte("rotated TLS key"), Perm: 0600},
			},
		},
		{
			name:  "replace a single file content",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"2.txt": {Content: []byte("2"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"2.txt": {Content: []byte("3"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"2.txt": {Content: []byte("3"), Perm: 0600},
			},
		},
		{
			name:  "replace a single file",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"2.txt": {Content: []byte("2"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"3.txt": {Content: []byte("3"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"3.txt": {Content: []byte("3"), Perm: 0600},
			},
		},
		{
			name:  "rename a single file",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"2.txt": {Content: []byte("2"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"3.txt": {Content: []byte("2"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"3.txt": {Content: []byte("2"), Perm: 0600},
			},
		},
		{
			name:  "add new files",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"tls.crt":         {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key":         {Content: []byte("TLS key"), Perm: 0600},
				"another_tls.crt": {Content: []byte("another TLS cert"), Perm: 0600},
				"another_tls.key": {Content: []byte("another TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"tls.crt":         {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key":         {Content: []byte("TLS key"), Perm: 0600},
				"another_tls.crt": {Content: []byte("another TLS cert"), Perm: 0600},
				"another_tls.key": {Content: []byte("another TLS key"), Perm: 0600},
			},
		},
		{
			name:  "delete a single file",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"2.txt": {Content: []byte("2"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
			},
		},
		{
			name:  "delete all files",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"1.txt": {Content: []byte("1"), Perm: 0600},
				"2.txt": {Content: []byte("2"), Perm: 0600},
			},
			filesToSync:   map[string]types.File{},
			expectedFiles: map[string]types.File{},
		},
		errorTestCase("directory unchanged on failed to create object directory", func() *fileSystem {
			fs := newRealFS()
			mkdirAll := fs.MkdirAll
			fs.MkdirAll = func(path string, perm os.FileMode) error {
				// Fail on the content dir.
				if !strings.Contains(path, "/staging/") {
					return errors.New("nuked")
				}
				return mkdirAll(path, perm)
			}
			return fs
		}),
		errorTestCase("directory unchanged on failed to create staging directory", func() *fileSystem {
			fs := newRealFS()
			mkdirAll := fs.MkdirAll
			fs.MkdirAll = func(path string, perm os.FileMode) error {
				// Fail on the staging dir.
				if strings.Contains(path, "/staging/") {
					return errors.New("nuked")
				}
				return mkdirAll(path, perm)
			}
			return fs
		}),
		errorTestCase("directory unchanged on failed to write the first file", func() *fileSystem {
			fs := newRealFS()
			fs.WriteFile = failToWriteNth(fs.WriteFile, 0)
			return fs
		}),
		errorTestCase("directory unchanged on failed to write the second file", func() *fileSystem {
			fs := newRealFS()
			fs.WriteFile = failToWriteNth(fs.WriteFile, 1)
			return fs
		}),
		errorTestCase("directory unchanged on failed to swap directories", func() *fileSystem {
			fs := newRealFS()
			fs.SwapDirectories = func(dirA, dirB string) error {
				return errors.New("nuked")
			}
			return fs
		}),
		{
			name: "directory synchronized then failing to remove temporary directory",
			newFS: func() *fileSystem {
				fs := newRealFS()
				fs.RemoveAll = func(path string) error {
					return errors.New("nuked")
				}
				return fs
			},
			existingFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"api.crt": {Content: []byte("rotated TLS cert"), Perm: 0600},
				"api.key": {Content: []byte("rotated TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"api.crt": {Content: []byte("rotated TLS cert"), Perm: 0600},
				"api.key": {Content: []byte("rotated TLS key"), Perm: 0600},
			},
			expectSyncError:                 true,
			expectLingeringStagingDirectory: true,
		},
		{
			name:  "invalid filename specified (relative path)",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				// This fails even though the actual resolved path is just "api.crt".
				// We simply do not handle paths in any way, we expect filenames.
				"home/../api.crt": {Content: []byte("rotated TLS cert"), Perm: 0600},
				"api.key":         {Content: []byte("rotated TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			expectSyncError: true,
		},
		{
			name:  "invalid filename specified (absolute path)",
			newFS: newRealFS,
			existingFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			filesToSync: map[string]types.File{
				"/api.crt": {Content: []byte("rotated TLS cert"), Perm: 0600},
				"api.key":  {Content: []byte("rotated TLS key"), Perm: 0600},
			},
			expectedFiles: map[string]types.File{
				"tls.crt": {Content: []byte("TLS cert"), Perm: 0600},
				"tls.key": {Content: []byte("TLS key"), Perm: 0600},
			},
			expectSyncError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Write the current directory contents.
			contentDir := filepath.Join(t.TempDir(), "secrets", "tls-cert")
			if tc.existingFiles != nil {
				adtesting.DirectoryState(tc.existingFiles).Write(t, contentDir, 0755)
			}

			// Replace with the object data.
			stagingDir := filepath.Join(t.TempDir(), "staging", "secrets", "tls-cert")
			err := sync(tc.newFS(), contentDir, 0755, stagingDir, tc.filesToSync)

			// Check the resulting state.
			adtesting.DirectoryState(tc.expectedFiles).CheckDirectoryMatches(t, contentDir, 0755)

			if (err != nil) != tc.expectSyncError {
				t.Errorf("Expected error from sync = %v, got %v", tc.expectSyncError, err)
			}

			if !tc.expectLingeringStagingDirectory {
				// Note that staging/secrets is still there, though. Which is fine.
				ensureDirectoryNotFound(t, stagingDir)
			}
		})
	}
}

type writeFileFunc func(path string, data []byte, perm os.FileMode) error

func failToWriteNth(writeFile writeFileFunc, n int) writeFileFunc {
	var c int
	return func(path string, data []byte, perm os.FileMode) error {
		i := c
		c++
		if i == n {
			return errors.New("nuked")
		}
		return writeFile(path, data, perm)
	}
}

func ensureDirectoryNotFound(t *testing.T, path string) {
	if _, stat := os.Stat(path); !os.IsNotExist(stat) {
		t.Errorf("Directory %q should not exist", path)
	}
}
