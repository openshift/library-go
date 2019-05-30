package filelock

import (
	"fmt"
	"os"
	"strconv"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog"
)

type lock struct {
	path string
}

func NewLock(path string) *lock {
	return &lock{
		path: path,
	}
}

func (l *lock) TryLock() (bool, error) {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL, 644)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			return false, nil
		}

		return false, fmt.Errorf("failed to create lock file %q: %v", l.path, err)
	}
	defer func() {
		err := f.Close()
		if err != nil {
			klog.Error(err)
		}
	}()

	_, err = f.Write([]byte(strconv.Itoa(os.Getpid())))
	if err != nil {
		// We have already acquired the lock so we shouldn't fail on additional info
		klog.Error(err)
	}

	return true, nil
}

func (l *lock) IsLocked() (bool, error) {
	_, err := os.Stat(l.path)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	// The bool return value doesn't matter but if someone was ignoring the error
	// it is safer to assume the file is locked.
	return true, fmt.Errorf("failed to determine if lock file %q is present: %v", l.path, err)
}

func (l *lock) Unlock() error {
	err := os.Remove(l.path)
	if err != nil {
		return fmt.Errorf("failed to remove lock file %q: %v", l.path, err)
	}

	return nil
}

func (l *lock) Path() string {
	return l.path
}
