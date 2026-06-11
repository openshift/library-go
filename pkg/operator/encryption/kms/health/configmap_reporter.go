package health

import (
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
)

const (
	// ConvergedKekConfigMapNamespace is where the mock converged-kek ConfigMap lives.
	ConvergedKekConfigMapNamespace = "openshift-config"
	// DefaultConvergedKekConfigMapName is the default ConfigMap name for mock KEK health input.
	DefaultConvergedKekConfigMapName = "encryption-kms-converged-kek"
	// ConvergedKekConfigMapDataKeyKekID holds the cluster-converged KMS kekId.
	ConvergedKekConfigMapDataKeyKekID = "converged-kek-id"
	// ConvergedKekConfigMapDataKeyConverged is an optional "true"/"false" override.
	// When omitted, a non-empty converged-kek-id is treated as converged.
	ConvergedKekConfigMapDataKeyConverged = "converged"
)

// MOCK_ConfigMapConvergedKEKReporter reads cluster-converged kekId from a ConfigMap in openshift-config.
// It is intended for development and testing until kms-health-reporter publishes real health input.
type MOCK_ConfigMapConvergedKEKReporter struct {
	lister    corev1listers.ConfigMapLister
	namespace string
	name      string
}

// NewMOCK_ConfigMapConvergedKEKReporter returns a mock reporter backed by the named ConfigMap.
// An empty name uses DefaultConvergedKekConfigMapName.
func NewMOCK_ConfigMapConvergedKEKReporter(lister corev1listers.ConfigMapLister, name string) *MOCK_ConfigMapConvergedKEKReporter {
	if name == "" {
		name = DefaultConvergedKekConfigMapName
	}
	return &MOCK_ConfigMapConvergedKEKReporter{
		lister:    lister,
		namespace: ConvergedKekConfigMapNamespace,
		name:      name,
	}
}

func (r *MOCK_ConfigMapConvergedKEKReporter) ConvergedKekID() (string, bool) {
	cm, err := r.lister.ConfigMaps(r.namespace).Get(r.name)
	if err != nil {
		klog.V(4).InfoS("converged kek configmap not available", "namespace", r.namespace, "name", r.name, "err", err)
		return "", false
	}
	return ConvergedKekFromConfigMap(cm)
}

// ConvergedKekFromConfigMap parses mock health input from a ConfigMap.
func ConvergedKekFromConfigMap(cm *corev1.ConfigMap) (kekID string, converged bool) {
	if cm == nil || cm.Data == nil {
		return "", false
	}
	kekID = strings.TrimSpace(cm.Data[ConvergedKekConfigMapDataKeyKekID])
	if kekID == "" {
		return "", false
	}
	if v, ok := cm.Data[ConvergedKekConfigMapDataKeyConverged]; ok {
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil || !parsed {
			return "", false
		}
	}
	return kekID, true
}
