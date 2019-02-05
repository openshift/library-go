package fmt

import (
	"strings"
	"testing"

	"github.com/go-log/log"
)

func TestFMTLogger(t *testing.T) {
	builder := &strings.Builder{}
	var logger log.Logger
	logger = &fmtLogger{writer: builder}
	logger.Log("a")
	logger.Log("b\n")
	logger.Logf("%s", "c")
	logger.Logf("%s\n", "d")
	expected := "a\nb\nc\nd\n"
	if builder.String() != expected {
		t.Fatalf("got %q, expected %q", builder.String(), expected)
	}
}
