package health

import (
	"sort"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

type TargetOperator string

const (
	kubeAPIServer      TargetOperator = "kube-apiserver"
	openshiftAPIServer TargetOperator = "openshift-apiserver"
	authAPIServer      TargetOperator = "auth-apiserver"
)

var supportedOperators = map[TargetOperator]struct {
	GVR schema.GroupVersionResource
	GVK schema.GroupVersionKind
}{
	kubeAPIServer: {
		GVR: schema.GroupVersionResource{Group: "operator.openshift.io", Version: "v1", Resource: "kubeapiservers"},
		GVK: schema.GroupVersionKind{Group: "operator.openshift.io", Version: "v1", Kind: "KubeAPIServer"},
	},
	authAPIServer: {
		GVR: schema.GroupVersionResource{Group: "operator.openshift.io", Version: "v1", Resource: "authentications"},
		GVK: schema.GroupVersionKind{Group: "operator.openshift.io", Version: "v1", Kind: "Authentication"},
	},
	openshiftAPIServer: {
		GVR: schema.GroupVersionResource{Group: "operator.openshift.io", Version: "v1", Resource: "openshiftapiservers"},
		GVK: schema.GroupVersionKind{Group: "operator.openshift.io", Version: "v1", Kind: "OpenShiftAPIServer"},
	},
}

func supportedOperatorKeys() []string {
	keys := make([]string, 0, len(supportedOperators))
	for k := range supportedOperators {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	return keys
}
