package print

import (
	"fmt"
	"testing"

	"github.com/go-log/log"
)

type printer struct{}

func (*printer) Print(v ...interface{}) {
	fmt.Println(v...)
}

func (*printer) Printf(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

func testLog(l log.Logger) {
	l.Log("test")
}

func testLogf(l log.Logger) {
	l.Logf("%s", "test")
}

func TestNew(t *testing.T) {
	l := New(&printer{})
	testLog(l)
	testLogf(l)
}
