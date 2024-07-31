package linearizer

import (
	"context"
	"fmt"
	"runtime/pprof"
	"unsafe"
)

const key = "openshift-linearizer-test"

func SetLabel(label string) {
	if label := GetLabel(); len(label) > 0 {
		panic(fmt.Errorf("wrong test setup - this goroutine has already been labeled with %q", label))
	}

	ctx := pprof.WithLabels(context.Background(), pprof.Labels(key, label))
	pprof.SetGoroutineLabels(ctx)
}

func GetLabel() string {
	labels := getProfLabel()
	return labels[key]
}

//go:linkname runtime_getProfLabel runtime/pprof.runtime_getProfLabel
func runtime_getProfLabel() unsafe.Pointer

func getProfLabel() map[string]string {
	l := (*map[string]string)(runtime_getProfLabel())
	if l == nil {
		return map[string]string{}
	}
	return *l
}
