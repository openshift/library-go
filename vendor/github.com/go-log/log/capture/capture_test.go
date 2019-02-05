package capture

import (
	"testing"

	"github.com/go-log/log"
)

func testLog(l log.Logger) {
	l.Log("test")
}

func testLogf(l log.Logger) {
	l.Logf("%s", "test")
}

func TestFMTLogger(t *testing.T) {
	logger := New()
	testLog(logger)
	testLogf(logger)
	expectedEntries := []string{"test", "test"}
	for i, expectedEntry := range expectedEntries {
		if i >= len(logger.Entries) {
			t.Errorf("missing expected entry %d: %q", i, expectedEntry)
			continue
		}
		actualEntry := logger.Entries[i]
		if actualEntry != expectedEntry {
			t.Errorf("unexpected entry %d: %q (expected %q)", i, actualEntry, expectedEntry)
		}
	}
	if len(logger.Entries) > len(expectedEntries) {
		t.Errorf("additional unexpected entries: %v", logger.Entries[len(expectedEntries):])
	}
}
