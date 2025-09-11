package certsyncpod

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/openshift/library-go/pkg/operator/events/eventstesting"
)

func TestWriteFiles(t *testing.T) {
	const (
		objectNamespace = "default"
		objectName      = "server_cert"
	)

	newRealFS := func() *fileSystem {
		fs := realFS
		return &fs
	}

	checkDirectoryContents := func(t *testing.T, contentDir string, files map[string][]byte) {
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
			if perm := info.Mode().Perm(); perm != 0600 {
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

	ensureParentDirectoryClean := func(t *testing.T, contentDir string) {
		// Make sure there are no leftovers in the parent directory.
		parentDir := filepath.Dir(contentDir)
		parentEntries, err := os.ReadDir(parentDir)
		if err != nil {
			t.Fatalf("Failed to read directory %q: %v", parentDir, err)
		}
		if n := len(parentEntries); n != 1 {
			t.Errorf("Unexpected number of entries in directory %q: %d", parentDir, n)
			for _, entry := range parentEntries {
				t.Logf("Parent directory entry: %q", entry.Name())
			}
		}
	}

	checkOnSuccess := func(t *testing.T, contentDir string, directoryData, objectData map[string][]byte, errs []error) {
		if len(errs) > 0 {
			t.Fatalf("Unexpected errors when writing new data object: %v", errs)
		}

		checkDirectoryContents(t, contentDir, objectData)
		ensureParentDirectoryClean(t, contentDir)
	}

	checkOnError := func(t *testing.T, contentDir string, directoryData, objectData map[string][]byte, errs []error) {
		if len(errs) == 0 {
			t.Error("Expected some errors, got none")
		}

		checkDirectoryContents(t, contentDir, directoryData)
		ensureParentDirectoryClean(t, contentDir)
	}

	type testCase struct {
		name          string
		newFS         func() *fileSystem
		directoryData map[string][]byte
		objectData    map[string][]byte
		checkState    func(t *testing.T, contentDir string, directoryData, objectData map[string][]byte, errs []error)
	}

	errorTestCase := func(name string, newFS func() *fileSystem) testCase {
		return testCase{
			name:  name,
			newFS: newFS,
			directoryData: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			objectData: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
			checkState: checkOnError,
		}
	}

	testCases := []testCase{
		{
			name:          "create target directory",
			newFS:         newRealFS,
			directoryData: nil,
			objectData: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			checkState: checkOnSuccess,
		},
		{
			name:  "update target directory change file content",
			newFS: newRealFS,
			directoryData: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			objectData: map[string][]byte{
				"tls.crt": []byte("rotated TLS cert"),
				"tls.key": []byte("rotated TLS key"),
			},
			checkState: checkOnSuccess,
		},
		{
			name:  "update target directory change filenames",
			newFS: newRealFS,
			directoryData: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			objectData: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
			checkState: checkOnSuccess,
		},
		errorTestCase("directory unchanged on failed to create object directory", func() *fileSystem {
			fs := newRealFS()
			fs.MkdirAll = func(path string, perm os.FileMode) error {
				return errors.New("nuked")
			}
			return fs
		}),
		errorTestCase("directory unchanged on failed to create temporary directory", func() *fileSystem {
			fs := newRealFS()
			fs.MkdirTemp = func(dir, pattern string) (string, error) {
				return "", errors.New("nuked")
			}
			return fs
		}),
		errorTestCase("directory unchanged on failed to write file", func() *fileSystem {
			fs := newRealFS()
			fs.WriteFile = func(path string, data []byte, perm os.FileMode) error {
				return errors.New("nuked")
			}
			return fs
		}),
		errorTestCase("directory unchanged on failed to swap directories", func() *fileSystem {
			fs := newRealFS()
			fs.SwapDirectoriesAtomic = func(dirA, dirB string) error {
				return errors.New("nuked")
			}
			return fs
		}),
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := eventstesting.NewTestingEventRecorder(t)

			// Write the current directory contents.
			contentDir := filepath.Join(t.TempDir(), "secrets", objectName)
			if tc.directoryData != nil {
				if err := os.MkdirAll(contentDir, 0755); err != nil {
					t.Fatalf("Failed to create content directory %q: %v", contentDir, err)
				}

				for filename, content := range tc.directoryData {
					targetPath := filepath.Join(contentDir, filename)
					if err := os.WriteFile(targetPath, content, 0600); err != nil {
						t.Fatalf("Failed to populate file %q: %v", targetPath, err)
					}
				}
			}

			// Replace with the object data.
			errs := writeFiles(tc.newFS(), recorder, objectNamespace, objectName, "secret",
				contentDir, tc.objectData, 0600)

			// Check the resulting state.
			tc.checkState(t, contentDir, tc.directoryData, tc.objectData, errs)
		})
	}

}
