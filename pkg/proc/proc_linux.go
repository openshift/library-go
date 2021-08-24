package proc

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"k8s.io/klog/v2"
)

// parseProcForZombies parses the current procfs mounted at /proc
// to find processes in the zombie state.
func parseProcForZombies(path string) (zombies []int, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	directories, err := file.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	for _, name := range directories {
		// Processes have numeric names. If the pid cannot
		// be parsed to an int, it is not a process pid.
		pid, err := strconv.ParseInt(name, 10, 0)
		if err != nil {
			continue
		}

		zombie, err := isZombie(path, name)
		if err != nil {
			klog.Errorf(
				"Failed to get the status of process with PID %s: %v",
				pid, err,
			)
			continue
		}
		if zombie {
			zombies = append(zombies, int(pid))
		}
	}

	return zombies, nil
}

// isZombie returns if a process is a zombie from /proc/[pid]/stat.
func isZombie(fsPath, pid string) (bool, error) {
	bytes, err := ioutil.ReadFile(filepath.Join(fsPath, pid, "stat"))
	if err != nil {
		return false, err
	}
	data := string(bytes)

	// /proc/[PID]/stat format is described in proc(5). The second field is
	// process name, enclosed in parentheses, and it can contain parentheses
	// inside. No other fields can have parentheses, so look for the last ')'.
	i := strings.LastIndexByte(data, ')')
	if i <= 2 || i >= len(data)-1 {
		return false, errors.Errorf("invalid stat data (no comm): %q", data)
	}

	// The state is field 3, which is the first two fields and a space after.
	return string(data[i+2]) == "Z", nil
}

// StartReaper starts a goroutine to reap processes periodically if called
// from a pid 1 process.
// If period is 0, then it is defaulted to 5 seconds.
// A caller can adjust the period depending on how many and how frequently zombie
// processes are created and need to be reaped.
func StartReaper(period time.Duration) {
	if os.Getpid() == 1 {
		const defaultReaperPeriodSeconds = 5
		if period == 0 {
			period = defaultReaperPeriodSeconds * time.Second
		}
		go func() {
			var zs []int
			var err error
			for {
				zs, err = parseProcForZombies("/proc")
				if err != nil {
					klog.Errorf("Failed to parse proc filesystem to find processes to reap: %v", err)
					continue
				}
				time.Sleep(period)
				for _, z := range zs {
					cpid, err := syscall.Wait4(z, nil, syscall.WNOHANG, nil)
					if err != nil {
						klog.Errorf("Unable to reap process pid %v: %v", cpid, err)
					}
				}
			}
		}()
	}
}
