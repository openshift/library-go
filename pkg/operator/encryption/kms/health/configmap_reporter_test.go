package health

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func TestConvergedKekFromConfigMap(t *testing.T) {
	tests := []struct {
		name          string
		cm            *corev1.ConfigMap
		wantKekID     string
		wantConverged bool
	}{
		{
			name:          "nil configmap",
			cm:            nil,
			wantConverged: false,
		},
		{
			name:          "empty data",
			cm:            &corev1.ConfigMap{},
			wantConverged: false,
		},
		{
			name: "converged with kek id only",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					ConvergedKekConfigMapDataKeyKekID: "kek-old",
				},
			},
			wantKekID:     "kek-old",
			wantConverged: true,
		},
		{
			name: "explicit converged true",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					ConvergedKekConfigMapDataKeyKekID:     "kek-new",
					ConvergedKekConfigMapDataKeyConverged: "true",
				},
			},
			wantKekID:     "kek-new",
			wantConverged: true,
		},
		{
			name: "explicit converged false",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					ConvergedKekConfigMapDataKeyKekID:     "kek-new",
					ConvergedKekConfigMapDataKeyConverged: "false",
				},
			},
			wantConverged: false,
		},
		{
			name: "whitespace trimmed",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					ConvergedKekConfigMapDataKeyKekID: "  kek-1  ",
				},
			},
			wantKekID:     "kek-1",
			wantConverged: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKekID, gotConverged := ConvergedKekFromConfigMap(tt.cm)
			if gotKekID != tt.wantKekID || gotConverged != tt.wantConverged {
				t.Fatalf("ConvergedKekFromConfigMap() = (%q, %v), want (%q, %v)", gotKekID, gotConverged, tt.wantKekID, tt.wantConverged)
			}
		})
	}
}

func TestMOCK_ConfigMapConvergedKEKReporter(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DefaultConvergedKekConfigMapName,
			Namespace: ConvergedKekConfigMapNamespace,
		},
		Data: map[string]string{
			ConvergedKekConfigMapDataKeyKekID: "kek-test",
		},
	}
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := indexer.Add(cm); err != nil {
		t.Fatal(err)
	}
	lister := corev1listers.NewConfigMapLister(indexer)
	reporter := NewMOCK_ConfigMapConvergedKEKReporter(lister, "")

	gotKekID, gotConverged := reporter.ConvergedKekID()
	if gotKekID != "kek-test" || !gotConverged {
		t.Fatalf("ConvergedKekID() = (%q, %v), want (%q, true)", gotKekID, gotConverged, "kek-test")
	}
}
