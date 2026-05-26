package health

import (
	"sort"
	"time"

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

type PluginHealthCondition struct {
	// KeyID is the sequential key identifier assigned by the key controller.
	KeyID string `json:"keyID"`
	// KEKID is the ID of the key used by the KMS provider for encryption/decryption.
	KEKID       string    `json:"kekID,omitempty"`
	Status      string    `json:"status"`
	LastChecked time.Time `json:"lastChecked"`
	Detail      string    `json:"detail,omitempty"`
}

func supportedOperatorKeys() []string {
	keys := make([]string, 0, len(supportedOperators))
	for k := range supportedOperators {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	return keys
}
