package resourceapply

import (
	"fmt"

	"github.com/golang/glog"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openshift/library-go/pkg/operator/events"
)

func reportCreateEvent(recorder events.Recorder, obj runtime.Object, originalErr error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	accessor, err := meta.Accessor(obj)
	if err != nil {
		glog.Errorf("Failed to get accessor for %+v", obj)
		return
	}
	objName := fmt.Sprintf("%s/%s", accessor.GetNamespace(), accessor.GetName())
	if len(accessor.GetNamespace()) == 0 {
		objName = accessor.GetName()
	}
	if originalErr == nil {
		recorder.Eventf(fmt.Sprintf("%sCreated", gvk.Kind), "Created %s %q because it was missing", gvk.Kind, objName)
		return
	}
	recorder.Warningf(fmt.Sprintf("%sCreateFailed", gvk.Kind), "Failed to create %s %q: %v", gvk.Kind, objName, originalErr)
}

func reportUpdateEvent(recorder events.Recorder, obj runtime.Object, originalErr error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	accessor, err := meta.Accessor(obj)
	if err != nil {
		glog.Errorf("Failed to get accessor for %+v", obj)
		return
	}
	objName := fmt.Sprintf("%s/%s", accessor.GetNamespace(), accessor.GetName())
	if len(accessor.GetNamespace()) == 0 {
		objName = accessor.GetName()
	}
	if originalErr == nil {
		recorder.Eventf(fmt.Sprintf("%sUpdated", gvk.Kind), "Updated %s %q because it changed", gvk.Kind, objName)
		return
	}
	recorder.Warningf(fmt.Sprintf("%sUpdateFailed", gvk.Kind), "Failed to update %s %q: %v", gvk.Kind, objName, originalErr)
}
