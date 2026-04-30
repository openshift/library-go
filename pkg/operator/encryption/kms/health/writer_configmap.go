package health

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// ConfigMapWriter uses merge-patch so a tick of class X updates data.X
// and leaves the other classes' keys alone. Consumers determine the
// "current" class by max data.<class>.timestamp; there is no separate
// pointer key.
//
// On the wire (data is map[string]string; values shown decoded):
//
//	data.ok        = {"timestamp":"...","observerPod":"...","keyIDHash":"..."}
//	data.not-ok    = {"timestamp":"...","observerPod":"...","detail":"...","keyIDHash":"..."}
//	data.rpc-error = {"timestamp":"...","observerPod":"...","detail":"..."}
//
// Self-heals on miss: if the CM is absent, Write creates it. Caller
// RBAC must therefore grant create in addition to get/update/patch on
// the named CM.
//
// Concurrency contract: one ConfigMap per monitor instance. Two
// monitors writing the same CM produce last-writer-wins on every key.
// Callers MUST encode instance identity in the CM name (the cmd-layer
// default is "kms-health-${POD_NAME}").
type ConfigMapWriter struct {
	client    kubernetes.Interface
	namespace string
	name      string
}

func NewConfigMapWriter(client kubernetes.Interface, namespace, name string) *ConfigMapWriter {
	return &ConfigMapWriter{
		client:    client,
		namespace: namespace,
		name:      name,
	}
}

type classEntry struct {
	Timestamp   string `json:"timestamp"`
	ObserverPod string `json:"observerPod"`
	Detail      string `json:"detail,omitempty"`
	KeyIDHash   string `json:"keyIDHash,omitempty"`
}

type configMapDataPatch struct {
	Data map[string]string `json:"data"`
}

func (w *ConfigMapWriter) Write(ctx context.Context, status HealthStatus) error {
	entry := classEntry{
		Timestamp:   status.Timestamp.UTC().Format(time.RFC3339),
		ObserverPod: status.ObserverPod,
		Detail:      status.Healthz.Detail,
		KeyIDHash:   status.KeyIDHash,
	}
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry for ConfigMap %s/%s: %w", w.namespace, w.name, err)
	}

	data := map[string]string{string(status.Healthz.Class): string(entryBytes)}
	patchBytes, err := json.Marshal(configMapDataPatch{Data: data})
	if err != nil {
		return fmt.Errorf("marshal patch for ConfigMap %s/%s: %w", w.namespace, w.name, err)
	}

	cms := w.client.CoreV1().ConfigMaps(w.namespace)
	_, err = cms.Patch(ctx, w.name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("patch ConfigMap %s/%s: %w", w.namespace, w.name, err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: w.name, Namespace: w.namespace},
		Data:       data,
	}
	_, err = cms.Create(ctx, cm, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create ConfigMap %s/%s: %w", w.namespace, w.name, err)
	}

	// Race: another writer created the CM between our Patch and Create.
	if _, err := cms.Patch(ctx, w.name, types.MergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch ConfigMap %s/%s after create race: %w", w.namespace, w.name, err)
	}
	return nil
}
