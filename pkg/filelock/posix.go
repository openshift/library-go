// +build linux darwin freebsd openbsd netbsd dragonfly

package filelock

import (
	"context"
	"errors"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

func syscallToCond(err error) (bool, error) {
	switch err {
	case nil:
		return true, nil
	case syscall.EAGAIN, syscall.EINTR:
		return false, nil
	default:
		return true, err
	}
}

// Posix file locks are identified with [i_node, pid] pair.
// Kernel will unlock them when your process terminates and they are left locked.
type Posix struct {
	fd uintptr
}

var ErrAlreadyHeld = errors.New("posix file lock is already held")
var ErrNoneHeld = errors.New("posix file lock is not associated with file descriptor")

func (l *Posix) ReadLock(ctx context.Context, fd uintptr) error {
	if l.fd != 0 && fd != l.fd {
		return ErrAlreadyHeld
	}

	l.fd = fd

	return wait.PollUntil(100*time.Millisecond, func() (bool, error) {
		return syscallToCond(syscall.FcntlFlock(fd, syscall.F_SETLK, &syscall.Flock_t{
			Type: syscall.F_RDLCK,
		}))
	}, ctx.Done())
}

func (l *Posix) WriteLock(ctx context.Context, fd uintptr) error {
	if l.fd != 0 && fd != l.fd {
		return ErrAlreadyHeld
	}

	l.fd = fd

	return wait.PollUntil(100*time.Millisecond, func() (bool, error) {
		return syscallToCond(syscall.FcntlFlock(fd, syscall.F_SETLK, &syscall.Flock_t{
			Type: syscall.F_WRLCK,
		}))
	}, ctx.Done())
}

func (l *Posix) Unlock(ctx context.Context) error {
	if l.fd == 0 {
		return ErrNoneHeld
	}

	return wait.PollUntil(100*time.Millisecond, func() (bool, error) {
		return syscallToCond(syscall.FcntlFlock(l.fd, syscall.F_SETLK, &syscall.Flock_t{
			Type: syscall.F_UNLCK,
		}))
	}, ctx.Done())
}
