// +build linux

package fileobserver

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObserver(t *testing.T) {
	dir, err := ioutil.TempDir("", "fileobserver-")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(dir)

	o, err := NewObserver()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	testFile := filepath.Join(dir, "testfile")

	firstObservedReactionFileChan := make(chan string)
	secondObservedReactionFileChan := make(chan string)

	fakeFirstReaction := func(name string, action ActionType) error {
		switch action {
		case FileCreated:
			firstObservedReactionFileChan <- name
		}
		return nil
	}

	fakeSecondReaction := func(name string, action ActionType) error {
		secondObservedReactionFileChan <- name
		return nil
	}

	o.AddReactor(fakeFirstReaction, testFile)
	o.AddReactor(fakeSecondReaction, testFile)

	stopChan := make(chan struct{})
	defer close(stopChan)
	go o.Run(stopChan)

	// Avoid flakes when the observer is not fully started
	time.Sleep(1 * time.Second)

	// Write something into the file
	ioutil.WriteFile(testFile, []byte("foo"), 0666)

	select {
	case observedFile := <-firstObservedReactionFileChan:
		if observedFile != testFile {
			t.Errorf("expected to get reaction on file %q, got file %q", testFile, observedFile)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout while waiting for the first reactor to react on change")
	}

	select {
	case observedFile := <-secondObservedReactionFileChan:
		if observedFile != testFile {
			t.Errorf("expected to get reaction on file %q, got file %q", testFile, observedFile)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout while waiting for the second reactor to react on change")
	}
}
