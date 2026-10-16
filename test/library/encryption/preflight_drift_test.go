package encryption

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestWaitForOperandPod(t *testing.T) {
	previousInterval := waitPollInterval
	waitPollInterval = time.Millisecond
	t.Cleanup(func() { waitPollInterval = previousInterval })

	running := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "operand", Labels: map[string]string{"apiserver": "true"}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pending := *running.DeepCopy()
	pending.Status.Phase = corev1.PodPending
	succeeded := *running.DeepCopy()
	succeeded.Status.Phase = corev1.PodSucceeded
	terminating := *running.DeepCopy()
	now := metav1.Now()
	terminating.DeletionTimestamp = &now
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("denied"))

	for _, tc := range []struct {
		name    string
		pods    []corev1.Pod
		err     error
		cancel  bool
		wantErr error
	}{
		{name: "mirror pod temporarily absent"},
		{name: "mirror pod pending", pods: []corev1.Pod{pending}},
		{name: "previous revision completed", pods: []corev1.Pod{succeeded}},
		{name: "previous revision terminating", pods: []corev1.Pod{terminating}},
		{name: "API temporarily unavailable", err: apierrors.NewServiceUnavailable("rolling out")},
		{name: "permanent API error", err: forbidden, wantErr: forbidden},
		{name: "caller cancels wait", cancel: true, wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client := fake.NewSimpleClientset()
			calls := 0
			client.PrependReactor("list", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
				if action.GetNamespace() != "operand-namespace" || action.(clienttesting.ListAction).GetListRestrictions().Labels.String() != "apiserver=true" {
					t.Fatalf("unexpected pod list action: %#v", action)
				}
				calls++
				if calls == 1 {
					if tc.cancel {
						cancel()
					}
					return true, &corev1.PodList{Items: tc.pods}, tc.err
				}
				return true, &corev1.PodList{Items: []corev1.Pod{running}}, nil
			})
			pod, err := waitForOperandPod(ctx, ClientSet{Kube: client}, "operand-namespace", "apiserver=true")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || pod != nil || calls != 1 {
					t.Fatalf("got pod=%v, err=%v, calls=%d; want error %v after one call", pod, err, calls, tc.wantErr)
				}
				return
			}
			if err != nil || pod == nil || pod.Name != running.Name || calls != 2 {
				t.Fatalf("got pod=%v, err=%v, calls=%d; want Running operand after two calls", pod, err, calls)
			}
		})
	}
}

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

	t.Run("SCC-assigned SecurityContext fields do not fail", func(t *testing.T) {
		preflightSpec := base.DeepCopy()
		seLevel := "s0:c26,c25"
		fsGroup := int64(1000700000)
		seccompType := corev1.SeccompProfileTypeRuntimeDefault
		preflightSpec.SecurityContext = &corev1.PodSecurityContext{
			SELinuxOptions: &corev1.SELinuxOptions{Level: seLevel},
			FSGroup:        &fsGroup,
			SeccompProfile: &corev1.SeccompProfile{Type: seccompType},
		}
		if diff := cmp.Diff(base, preflightSpec, opts...); diff != "" {
			t.Fatalf("expected SCC-assigned SecurityContext to be ignored, got:\n%s", diff)
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
