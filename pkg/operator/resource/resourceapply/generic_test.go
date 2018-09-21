package resourceapply

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestApplyDirectly(t *testing.T) {
	requiredObj, gvk, err := genericCodec.Decode([]byte(`apiVersion: v1
kind: Namespace
metadata:
  name: openshift-apiserver
  labels:
    openshift.io/run-level: "1"
`), nil, nil)
	t.Log(spew.Sdump(requiredObj))
	t.Log(spew.Sdump(gvk))
	if err != nil {
		t.Fatal(err)
	}
}
