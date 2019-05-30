package filelock

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIsLocked(t *testing.T) {
	dir, err := ioutil.TempDir("", "test-is-locked")
	if err != nil {
		t.Fatalf("failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	l := NewLock(filepath.Join(dir, "lock_file"))
	locked, err := l.IsLocked()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if locked {
		t.Fatal("With no file present it shouldn't be locked")
	}

	// First lock should succeed
	locked, err = l.TryLock()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !locked {
		t.Fatal("Locking failed.")
	}

	locked, err = l.IsLocked()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !locked {
		t.Fatal("With lock file present it should be locked")
	}

	// Second lock should fail
	locked, err = l.TryLock()
	expErr := fmt.Errorf("failed to create lock file %q: open %s: file exists", l.Path(), l.Path())
	if !reflect.DeepEqual(err, expErr) {
		t.Fatalf("Expected error %#v, got %#v", expErr, err)
	}
	if locked {
		t.Fatal("Locking should have failed")
	}

	locked, err = l.IsLocked()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !locked {
		t.Fatal("With lock file present it should be locked")
	}

	err = l.Unlock()
	if err != nil {
		t.Errorf("Failed to unlock file: %v", err)
	}

	locked, err = l.IsLocked()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if locked {
		t.Fatal("With no lock file present it should be unlocked")
	}

	// Unlocking unlocked (not present file lock) should fail
	err = l.Unlock()
	expErr = fmt.Errorf("failed to remove lock file %q: remove %s: no such file or directory", l.Path(), l.Path())
	if !reflect.DeepEqual(err, expErr) {
		t.Fatalf("Expected error %#v, got %#v", expErr, err)
	}
}
