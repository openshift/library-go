package encryption

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
)

func TestDefaultPreflightPodSpecDriftIgnore(t *testing.T) {
	base := &corev1.PodSpec{
		HostNetwork:       true,
		PriorityClassName: "system-cluster-critical",
		RestartPolicy:     corev1.RestartPolicyAlways,
		Containers: []corev1.Container{{
			Name:  "apiserver",
			Image: "kas:latest",
		}},
	}
	opts := []cmp.Option{
		cmpopts.IgnoreFields(corev1.PodSpec{}, DefaultPreflightPodSpecDriftIgnore...),
		cmpopts.EquateEmpty(),
	}

	t.Run("ignore list names are PodSpec fields", func(t *testing.T) {
		typ := reflect.TypeOf(corev1.PodSpec{})
		for _, name := range DefaultPreflightPodSpecDriftIgnore {
			if _, ok := typ.FieldByName(name); !ok {
				t.Errorf("DefaultPreflightPodSpecDriftIgnore entry %q is not a PodSpec field", name)
			}
		}
	})

	t.Run("identical specs", func(t *testing.T) {
		other := base.DeepCopy()
		if diff := cmp.Diff(base, other, opts...); diff != "" {
			t.Fatalf("expected no drift, got:\n%s", diff)
		}
	})

	t.Run("ignored workload fields do not fail", func(t *testing.T) {
		preflightSpec := base.DeepCopy()
		preflightSpec.Containers = []corev1.Container{{Name: "kms-preflight-check", Image: "op:latest"}}
		preflightSpec.InitContainers = []corev1.Container{{Name: "plugin", Image: "plugin:latest"}}
		preflightSpec.RestartPolicy = corev1.RestartPolicyNever
		preflightSpec.ServiceAccountName = "kms-preflight"
		preflightSpec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "kms-preflight-dockercfg"}}
		if diff := cmp.Diff(base, preflightSpec, opts...); diff != "" {
			t.Fatalf("expected ignored fields to be skipped, got:\n%s", diff)
		}
	})

	t.Run("unexpected HostNetwork drift fails", func(t *testing.T) {
		preflightSpec := base.DeepCopy()
		preflightSpec.HostNetwork = false
		diff := cmp.Diff(base, preflightSpec, opts...)
		if diff == "" {
			t.Fatal("expected HostNetwork drift")
		}
		if !strings.Contains(diff, "HostNetwork") {
			t.Fatalf("expected HostNetwork in diff, got:\n%s", diff)
		}
	})

	t.Run("custom ignore suppresses field", func(t *testing.T) {
		preflightSpec := base.DeepCopy()
		preflightSpec.HostNetwork = false
		ignore := append([]string{}, DefaultPreflightPodSpecDriftIgnore...)
		ignore = append(ignore, "HostNetwork")
		diff := cmp.Diff(base, preflightSpec,
			cmpopts.IgnoreFields(corev1.PodSpec{}, ignore...),
			cmpopts.EquateEmpty(),
		)
		if diff != "" {
			t.Fatalf("expected HostNetwork to be ignored, got:\n%s", diff)
		}
	})
}
