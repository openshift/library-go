package controllers

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

func NewResourceVersionProtector(delegate cache.SharedIndexInformer) cache.SharedIndexInformer {
	return &resourceVersionProtector{delegate}
}

type resourceVersionProtector struct {
	cache.SharedIndexInformer
}

func (rvp *resourceVersionProtector) AddEventHandler(delegate cache.ResourceEventHandler) {
	rvp.SharedIndexInformer.AddEventHandler(eventHandlerWrapper(delegate))
}

func eventHandlerWrapper(delegate cache.ResourceEventHandler) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) { delegate.OnAdd(obj) },
		UpdateFunc: func(old, new interface{}) {
			newRuntimeObj, ok := new.(runtime.Object)
			if !ok {
				utilruntime.HandleError(fmt.Errorf("updated object %+v is not runtime Object", newRuntimeObj))
				return
			}
			oldRunTimeObj, ok := old.(runtime.Object)
			if !ok {
				utilruntime.HandleError(fmt.Errorf("updated object %+v is not runtime Object", oldRunTimeObj))
				return
			}
			newMetaAccessor, err := meta.Accessor(newRuntimeObj)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("unable to get the meta accessor from %+v due to %v", newRuntimeObj, err))
				return
			}
			oldMetaAccessor, err := meta.Accessor(oldRunTimeObj)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("unable to get the meta accessor from %+v due to %v", oldRunTimeObj, err))
				return
			}
			if newMetaAccessor.GetResourceVersion() == oldMetaAccessor.GetResourceVersion() {
				// periodic resync will send update events two different versions of the same obj will always have different RVs.
				// TODO: rm
				klog.Info("periodic resync detected")
				return
			}

			// TODO: rm
			klog.Infof("Update function diff: %v", diff.ObjectDiff(old, new))
			delegate.OnUpdate(old, new)
		},
		DeleteFunc: func(obj interface{}) { delegate.OnDelete(obj) },
	}
}
