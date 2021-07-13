// +build linux

package flock

import (
	"os"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

// TryLock tries to acquire an exclusive lock on a file
// until it succeeds, an error is returned or the timeout is reached.
//
// The callers MUST call the corresponding Unlock method to release the lock and associated resources except when an error
// is returned (including the timeout).
//
// This method is safe for concurrent access.
//
// Note the given timeout shouldn't be less than 1 second.
func (f *FLock) TryLock(timeout time.Duration) error {
	f.locker.Lock()
	defer f.locker.Unlock()
	if err := f.openLockFile(); err != nil {
		return err
	}
	if err := wait.Poll(300*time.Millisecond, timeout, f.tryLock); err != nil {
		if closeErr := f.closeLockedFile(); closeErr != nil {
			return closeErr
		}
		return err
	}
	return nil
}

// Unlock releases the lock and associated resources.
func (f *FLock) Unlock() error {
	f.locker.Lock()
	defer f.locker.Unlock()

	if err := syscall.Flock(int(f.lockedFile.Fd()), syscall.LOCK_UN); err != nil {
		return err
	}

	return f.closeLockedFile()
}

func (f *FLock) tryLock() (bool, error) {
	err := syscall.Flock(int(f.lockedFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)

	if err == nil {
		return true, nil // we have a lock
	}
	if err == syscall.EWOULDBLOCK {
		return false, nil // another process holds a lock on the file
	}
	return false, err // an unknown err
}

func (f *FLock) openLockFile() error {
	if f.lockedFile != nil {
		return nil
	}
	file, err := os.OpenFile(f.lockFilePath, os.O_CREATE|os.O_RDONLY, os.FileMode(0644))
	if err != nil {
		return err
	}

	f.lockedFile = file
	return nil
}

func (f *FLock) closeLockedFile() error {
	if err := f.lockedFile.Close(); err != nil {
		return err
	}
	f.lockedFile = nil
	return nil
}
