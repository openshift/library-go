package info

import (
	"fmt"
	"testing"

	"github.com/go-log/log"
)

type info struct {}

func (*info) Info(v ...interface{}) {
	fmt.Println(v...)
}

func (*info) Infof(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

func testLog(l log.Logger) {
	l.Log("test")
}

func testLogf(l log.Logger) {
	l.Logf("%s", "test")
}

func TestNew(t *testing.T) {
	l := New(&info{})
	testLog(l)
	testLogf(l)
}
