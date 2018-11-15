// +build !linux

package fileobserver

func init() {
	NewObserver = func() (Observer, error) {
		panic("file observer is not supported on this platform")
	}
}
