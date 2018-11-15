// +build linux

package fileobserver

import (
	"fmt"
	"path/filepath"
	"sync"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/golang/glog"
	"github.com/sigma/go-inotify"
)

type linuxObserver struct {
	watcher       *inotify.Watcher
	reactors      map[string][]reactorFn
	reactorsMutex sync.RWMutex
}

func init() {
	NewObserver = newLinuxObserver
}

func newLinuxObserver() (Observer, error) {
	inotifyWatcher, err := inotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &linuxObserver{
		watcher:  inotifyWatcher,
		reactors: map[string][]reactorFn{},
	}, nil
}

// AddReactor adds a new reactor to the observer. It takes a reactor function that will be called when a change is observed
// to any file (or directory) given as the second argument.
func (o *linuxObserver) AddReactor(reactor reactorFn, filenames ...string) Observer {
	o.reactorsMutex.Lock()
	defer o.reactorsMutex.Unlock()
	for _, f := range filenames {
		glog.V(3).Infof("Adding reactor for file %q", f)
		o.watcher.AddWatch(filepath.Dir(f), inotify.IN_MODIFY|inotify.IN_CREATE|inotify.IN_DELETE)
		o.reactors[f] = append(o.reactors[f], reactor)
	}
	return o
}

func maskToAction(mask uint32) ActionType {
	switch mask {
	case inotify.IN_MODIFY:
		return FileModified
	case inotify.IN_DELETE:
		return FileDeleted
	case inotify.IN_CREATE:
		return FileCreated
	default:
		// NOTE: This should never happen (unless the implementation or syscalls changed.
		panic(fmt.Sprintf("unhandled action: %v", mask))
	}
}

func (o *linuxObserver) reportWatcherErrors(stopCh <-chan struct{}) {
	for {
		select {
		case err := <-o.watcher.Error:
			glog.Error(err)
		case <-stopCh:
			return
		}
	}
}

func (o *linuxObserver) processWatcherEvents(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash(func(panicReason interface{}) {
		o.reactorsMutex.Unlock()
		o.watcher.Close()
	})
	for {
		select {
		case event := <-o.watcher.Event:
			o.reactorsMutex.Lock()
			if _, hasReactor := o.reactors[event.Name]; !hasReactor {
				continue
			}
			glog.Infof("Observed change: %s", event.String())
			for i := range o.reactors[event.Name] {
				if err := o.reactors[event.Name][i](event.Name, maskToAction(event.Mask)); err != nil {
					glog.Errorf("Reactor for %q failed: %v", event.Name, err)
				}
			}
			o.reactorsMutex.Unlock()
		case <-stopCh:
			o.watcher.Close()
			return
		}
	}
}

// Run will start the file observer. When the stop channel is closed, the observer will shut down.
func (o *linuxObserver) Run(stopCh <-chan struct{}) {
	glog.Info("Starting file observer")
	defer glog.Infof("Shutting down file observer")

	// Process all errors from the watcher in parallel
	go o.reportWatcherErrors(stopCh)

	// Process all watch events
	go o.processWatcherEvents(stopCh)

	// Wait for the stop signal to shut down watcher and queue
	<-stopCh
}
