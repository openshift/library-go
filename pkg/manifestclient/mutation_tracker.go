package manifestclient

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"sync"
)

type AllActionsTracker struct {
	lock sync.RWMutex

	ActionToTracker map[Action]*ActionTracker
}

type Action string

const (
	// this is really a subset of patch, but we treat it separately because it is useful to do so
	ActionApply        Action = "server-side-apply"
	ActionApplyStatus  Action = "server-side-apply-status"
	ActionUpdate       Action = "update"
	ActionUpdateStatus Action = "update-status"
	ActionCreate       Action = "create"
	ActionDelete       Action = "delete"
)

type ActionMetadata struct {
	Action    Action
	GVR       schema.GroupVersionResource
	Namespace string
	Name      string
}

type ActionTracker struct {
	Action            Action
	ResourceToTracker map[schema.GroupVersionResource]*ResourceTracker
}

type ResourceTracker struct {
	GVR                schema.GroupVersionResource
	NamespaceToTracker map[string]*NamespaceTracker
}

type NamespaceTracker struct {
	Namespace     string
	NameToTracker map[string]*NameTracker
}

type NameTracker struct {
	Name               string
	SerializedRequests []SerializedRequest
}

type SerializedRequest struct {
	Options []byte
	Body    []byte
}

func (a *AllActionsTracker) AddRequest(metadata ActionMetadata, request SerializedRequest) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.ActionToTracker == nil {
		a.ActionToTracker = map[Action]*ActionTracker{}
	}
	if _, ok := a.ActionToTracker[metadata.Action]; !ok {
		a.ActionToTracker[metadata.Action] = &ActionTracker{Action: metadata.Action}
	}
	a.ActionToTracker[metadata.Action].AddRequest(metadata, request)
}

func (a *AllActionsTracker) ListActions() []Action {
	a.lock.Lock()
	defer a.lock.Unlock()

	return sets.KeySet(a.ActionToTracker).UnsortedList()
}

func (a *AllActionsTracker) MutationsForAction(action Action) *ActionTracker {
	a.lock.RLock()
	defer a.lock.RUnlock()

	return a.ActionToTracker[action]
}

func (a *AllActionsTracker) MutationsForMetadata(metadata ActionMetadata) []SerializedRequest {
	a.lock.RLock()
	defer a.lock.RUnlock()

	actionTracker := a.MutationsForAction(metadata.Action)
	if actionTracker == nil {
		return nil
	}
	resourceTracker := actionTracker.MutationsForResource(metadata.GVR)
	if resourceTracker == nil {
		return nil
	}
	namespaceTracker := resourceTracker.MutationsForNamespace(metadata.Namespace)
	if namespaceTracker == nil {
		return nil
	}
	nameTracker := namespaceTracker.MutationsForName(metadata.Name)
	if nameTracker == nil {
		return nil
	}
	return nameTracker.SerializedRequests
}

func (a *ActionTracker) AddRequest(metadata ActionMetadata, request SerializedRequest) {
	if a.ResourceToTracker == nil {
		a.ResourceToTracker = map[schema.GroupVersionResource]*ResourceTracker{}
	}
	if _, ok := a.ResourceToTracker[metadata.GVR]; !ok {
		a.ResourceToTracker[metadata.GVR] = &ResourceTracker{GVR: metadata.GVR}
	}
	a.ResourceToTracker[metadata.GVR].AddRequest(metadata, request)
}

func (a *ActionTracker) ListResources() []schema.GroupVersionResource {
	return sets.KeySet(a.ResourceToTracker).UnsortedList()
}

func (a *ActionTracker) MutationsForResource(gvr schema.GroupVersionResource) *ResourceTracker {
	return a.ResourceToTracker[gvr]
}

func (a *ResourceTracker) AddRequest(metadata ActionMetadata, request SerializedRequest) {
	if a.NamespaceToTracker == nil {
		a.NamespaceToTracker = map[string]*NamespaceTracker{}
	}
	if _, ok := a.NamespaceToTracker[metadata.Namespace]; !ok {
		a.NamespaceToTracker[metadata.Namespace] = &NamespaceTracker{Namespace: metadata.Namespace}
	}
	a.NamespaceToTracker[metadata.Namespace].AddRequest(metadata, request)
}

func (a *ResourceTracker) ListNamespaces() []string {
	return sets.KeySet(a.NamespaceToTracker).UnsortedList()
}

func (a *ResourceTracker) MutationsForNamespace(namespace string) *NamespaceTracker {
	return a.NamespaceToTracker[namespace]
}

func (a *NamespaceTracker) AddRequest(metadata ActionMetadata, request SerializedRequest) {
	if a.NameToTracker == nil {
		a.NameToTracker = map[string]*NameTracker{}
	}
	if _, ok := a.NameToTracker[metadata.Name]; !ok {
		a.NameToTracker[metadata.Name] = &NameTracker{Name: metadata.Name}
	}
	a.NameToTracker[metadata.Name].AddRequest(request)
}

func (a *NamespaceTracker) ListNames() []string {
	return sets.KeySet(a.NameToTracker).UnsortedList()
}

func (a *NamespaceTracker) MutationsForName(name string) *NameTracker {
	return a.NameToTracker[name]
}

func (a *NameTracker) AddRequest(request SerializedRequest) {
	if a.SerializedRequests == nil {
		a.SerializedRequests = []SerializedRequest{}
	}
	a.SerializedRequests = append(a.SerializedRequests, request)
}
