// +build linux darwin freebsd openbsd netbsd dragonfly

package filelock

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
)

// Posix locks are identified by [i_node, pid]
// To test it properly we would have to fork here, but Golang doesn't support it,
// so we will test the single PID case.
//
// (I guess we might be able to use ForkExec to somehow target back this unit test
// but having integration test is likely to be easier.)
//
// TODO: add multi (PID) writer integration test

func TestReadLock(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	file, err := os.Create(dir + "/lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	ctx := context.Background()

	l := Posix{}

	// First ReadLock
	err = l.ReadLock(ctx, file.Fd())
	if err != nil {
		t.Fatal(err)
	}

	// Second ReadLock
	err = l.ReadLock(ctx, file.Fd())
	if err != nil {
		t.Fatal(err)
	}

	// a ReadLock on different fd should fail
	err = l.ReadLock(ctx, uintptr(42))
	if err != ErrAlreadyHeld {
		t.Fatalf("expected %v, got: %v", ErrAlreadyHeld, err)
	}

	err = l.Unlock(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteLock(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	file, err := os.Create(dir + "/lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	ctx := context.Background()

	l := Posix{}

	// First WriteLock
	err = l.WriteLock(ctx, file.Fd())
	if err != nil {
		t.Fatal(err)
	}

	// Second WriteLock
	err = l.WriteLock(ctx, file.Fd())
	if err != nil {
		t.Fatal(err)
	}

	// a WriteLock on different fd should fail
	err = l.WriteLock(ctx, uintptr(42))
	if err != ErrAlreadyHeld {
		t.Fatalf("expected %v, got: %v", ErrAlreadyHeld, err)
	}

	err = l.Unlock(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnlock(t *testing.T) {
	l := Posix{}

	ctx := context.Background()

	err := l.Unlock(ctx)
	if err != ErrNoneHeld {
		t.Fatalf("expected %v, got: %v", ErrAlreadyHeld, err)
	}
}
