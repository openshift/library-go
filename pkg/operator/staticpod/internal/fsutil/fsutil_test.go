package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileFsync(t *testing.T) {
	testCases := []struct {
		name        string
		setup       func(t *testing.T) string
		data        []byte
		perm        os.FileMode
		expectError bool
	}{
		{
			name: "writes file with correct content and permissions",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "test.txt")
			},
			data: []byte("hello world"),
			perm: 0600,
		},
		{
			name: "creates file in nonexistent directory fails",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nodir", "test.txt")
			},
			data:        []byte("hello"),
			perm:        0600,
			expectError: true,
		},
		{
			name: "overwrites existing file",
			setup: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "test.txt")
				if err := os.WriteFile(p, []byte("old content"), 0600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			data: []byte("new content"),
			perm: 0600,
		},
		{
			name: "writes empty file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "empty.txt")
			},
			data: []byte{},
			perm: 0644,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setup(t)
			err := WriteFileFsync(path, tc.data, tc.perm)

			if tc.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read back file: %v", err)
			}
			if string(got) != string(tc.data) {
				t.Errorf("content mismatch: got %q, want %q", got, tc.data)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("failed to stat file: %v", err)
			}
			if info.Mode().Perm() != tc.perm {
				t.Errorf("permission mismatch: got %o, want %o", info.Mode().Perm(), tc.perm)
			}
		})
	}
}

func TestFsync(t *testing.T) {
	t.Run("syncs existing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := Fsync(path); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("syncs existing directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := Fsync(dir); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("fails on nonexistent path", func(t *testing.T) {
		if err := Fsync(filepath.Join(t.TempDir(), "nonexistent")); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
