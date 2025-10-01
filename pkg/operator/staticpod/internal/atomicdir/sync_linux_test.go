//go:build linux

package atomicdir

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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
		existingFiles map[string][]byte
		// filesToSync will be synchronized into the target directory.
		filesToSync map[string][]byte
		// expectedFiles contains the files that are expected to be in the target directory after sync is called.
		expectedFiles map[string][]byte
		// expectSyncError check the return value from Sync.
		expectSyncError bool
		// expectLingeringStagingDirectory can be set to true to expect the temporary directory not to be removed.
		expectLingeringStagingDirectory bool
	}

	errorTestCase := func(name string, newFS func() *fileSystem) testCase {
		return testCase{
			name:  name,
			newFS: newFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
			expectedFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			expectSyncError: true,
		}
	}

	testCases := []testCase{
		{
			name:          "target directory does not exist",
			newFS:         newRealFS,
			existingFiles: nil,
			filesToSync: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			expectedFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
		},
		{
			name:          "target directory is empty",
			newFS:         newRealFS,
			existingFiles: map[string][]byte{},
			filesToSync: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			expectedFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
		},
		{
			name:  "target directory already synchronized",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			expectedFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
		},
		{
			name:  "change file contents preserving the filenames",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"tls.crt": []byte("rotated TLS cert"),
				"tls.key": []byte("rotated TLS key"),
			},
			expectedFiles: map[string][]byte{
				"tls.crt": []byte("rotated TLS cert"),
				"tls.key": []byte("rotated TLS key"),
			},
		},
		{
			name:  "change filenames preserving the file contents",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"api.crt": []byte("TLS cert"),
				"api.key": []byte("TLS key"),
			},
			expectedFiles: map[string][]byte{
				"api.crt": []byte("TLS cert"),
				"api.key": []byte("TLS key"),
			},
		},
		{
			name:  "change filenames and file contents",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
			expectedFiles: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
		},
		{
			name:  "replace a single file content",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("3"),
			},
			expectedFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("3"),
			},
		},
		{
			name:  "replace a single file",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync: map[string][]byte{
				"1.txt": []byte("1"),
				"3.txt": []byte("3"),
			},
			expectedFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"3.txt": []byte("3"),
			},
		},
		{
			name:  "rename a single file",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync: map[string][]byte{
				"1.txt": []byte("1"),
				"3.txt": []byte("2"),
			},
			expectedFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"3.txt": []byte("2"),
			},
		},
		{
			name:  "add new files",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"tls.crt":         []byte("TLS cert"),
				"tls.key":         []byte("TLS key"),
				"another_tls.crt": []byte("another TLS cert"),
				"another_tls.key": []byte("another TLS key"),
			},
			expectedFiles: map[string][]byte{
				"tls.crt":         []byte("TLS cert"),
				"tls.key":         []byte("TLS key"),
				"another_tls.crt": []byte("another TLS cert"),
				"another_tls.key": []byte("another TLS key"),
			},
		},
		{
			name:  "delete a single file",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync: map[string][]byte{
				"1.txt": []byte("1"),
			},
			expectedFiles: map[string][]byte{
				"1.txt": []byte("1"),
			},
		},
		{
			name:  "delete all files",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync:   map[string][]byte{},
			expectedFiles: map[string][]byte{},
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
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
			expectedFiles: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
			expectSyncError:                 true,
			expectLingeringStagingDirectory: true,
		},
		{
			name:  "invalid filename specified (relative path)",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				// This fails even though the actual resolved path is just "api.crt".
				// We simply do not handle paths in any way, we expect filenames.
				"home/../api.crt": []byte("rotated TLS cert"),
				"api.key":         []byte("rotated TLS key"),
			},
			expectedFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			expectSyncError: true,
		},
		{
			name:  "invalid filename specified (absolute path)",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"/api.crt": []byte("rotated TLS cert"),
				"api.key":  []byte("rotated TLS key"),
			},
			expectedFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			expectSyncError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Write the current directory contents.
			contentDir := filepath.Join(t.TempDir(), "secrets", "tls-cert")
			if tc.existingFiles != nil {
				if err := os.MkdirAll(contentDir, 0700); err != nil {
					t.Fatalf("Failed to create content directory %q: %v", contentDir, err)
				}

				for filename, content := range tc.existingFiles {
					targetPath := filepath.Join(contentDir, filename)
					if err := os.WriteFile(targetPath, content, 0600); err != nil {
						t.Fatalf("Failed to populate file %q: %v", targetPath, err)
					}
				}
			}

			// Replace with the object data.
			stagingDir := filepath.Join(t.TempDir(), "staging", "secrets", "tls-cert")
			err := sync(tc.newFS(), contentDir, 0700, stagingDir, tc.filesToSync, 0600)

			// Check the resulting state.
			checkDirectoryContents(t, contentDir, 0700, tc.expectedFiles, 0600)

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

func checkDirectoryContents(t *testing.T, contentDir string, contentDirPerm os.FileMode, files map[string][]byte, filePerm os.FileMode) {
	// Ensure the content directory permissions match.
	stat, err := os.Stat(contentDir)
	if err != nil {
		t.Fatalf("Failed to stat %q: %v", contentDir, err)
	}
	if perm := stat.Mode().Perm(); perm != contentDirPerm {
		t.Errorf("Permissions mismatch detected for %q: expected %v, got %v", contentDir, contentDirPerm, perm)
	}

	// Ensure the content directory is in sync.
	entries, err := os.ReadDir(contentDir)
	if err != nil {
		t.Fatalf("Failed to read directory %q: %v", contentDir, err)
	}
	writtenData := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("Failed to read file information for %q: %v", entry.Name(), err)
		}
		if perm := info.Mode().Perm(); perm != filePerm {
			t.Errorf("Unexpected file permissions for %q: %v", entry.Name(), perm)
		}

		content, err := os.ReadFile(filepath.Join(contentDir, entry.Name()))
		if err != nil {
			t.Fatalf("Failed to read file %q: %v", entry.Name(), err)
		}
		writtenData[entry.Name()] = content
	}
	if !cmp.Equal(writtenData, files) {
		t.Errorf("Unexpected directory content:\n%s\n", cmp.Diff(files, writtenData))
	}
}

func ensureDirectoryNotFound(t *testing.T, path string) {
	if _, stat := os.Stat(path); !os.IsNotExist(stat) {
		t.Errorf("Directory %q should not exist", path)
	}
}
