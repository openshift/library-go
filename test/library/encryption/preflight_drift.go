package encryption

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/preflight"
)

// DefaultPreflightPodSpecDriftIgnore lists PodSpec field names skipped by
// AssertNoPreflightConfigDrift via cmpopts.IgnoreFields. Unknown diffs outside
// this list fail the drift check.
//
// Keep entries as exported Go field names (e.g. "HostNetwork"), not JSON tags.
// Prefer a short list: fields that are nil/zero on both sides already compare equal, so
// only ignore fields we know differ by design between preflight and the operand.
var DefaultPreflightPodSpecDriftIgnore = []string{
	// --- Workload-owned: preflight is a one-shot checker, not the apiserver ---
	// Preflight runs kms-preflight-check (+ KMS plugin init/sidecar); operands run apiserver containers.
	"Containers",
	"InitContainers",
	"EphemeralContainers",
	// Volume mounts follow the containers above (encryption-config, sockets, etc.).
	"Volumes",
	// Preflight uses RestartPolicy=Never; operands typically Always.
	"RestartPolicy",
	// Preflight uses its own SA (kms-preflight) vs the operand service account.
	"ServiceAccountName",
	"DeprecatedServiceAccount",
	"AutomountServiceAccountToken",
	// OpenShift injects the SA dockercfg onto the preflight pod; static KAS pods typically have none.
	"ImagePullSecrets",
	// One-shot job semantics; operands are long-running.
	"ActiveDeadlineSeconds",
	"TerminationGracePeriodSeconds",

	// Filled by the scheduler on Running pods; preflight and operand will always share a control plane node one way or another.
	"NodeName",
	// Preflight sets master nodeSelector; static KAS pods are placed differently.
	"NodeSelector",
	// Toleration sets differ (preflight: two master tolerations; KAS: Exists; oauth: master+unreachable+not-ready).
	"Tolerations",
	// oauth-apiserver injects anti-affinity in code; preflight has none.
	"Affinity",
	// Preflight template still uses system-cluster-critical; operands use system-node-critical.
	"PriorityClassName",
	// KAS sets an explicit numeric priority; preflight leaves it to the PriorityClass.
	"Priority",

	// SCC admission sets SELinuxOptions, FSGroup, SeccompProfile etc. per SA binding;
	// preflight and operand run under different service accounts so values always differ.
	"SecurityContext",
}

// AssertNoPreflightConfigDrift fetches the preflight pod and a Running operand pod matching
// labelSelector, then fails if cmp.Diff reports unexpected PodSpec drift.
// Call this separately from AssertPreflightDeploy (e.g. from TestPreflightDeployAndPodMatchesOperand).
func AssertNoPreflightConfigDrift(ctx context.Context, t testing.TB, clientSet ClientSet, namespace, labelSelector string) {
	t.Helper()
	require.NotEmpty(t, namespace)
	require.NotEmpty(t, labelSelector)

	preflightPod, err := clientSet.Kube.CoreV1().Pods(namespace).Get(ctx, preflight.PodName, metav1.GetOptions{})
	require.NoError(t, err, "preflight pod %s/%s", namespace, preflight.PodName)

	targetPod := findAnyOperandPod(ctx, t, clientSet, namespace, labelSelector)
	require.NotNil(t, targetPod, "no Running pod in %s matching %q", namespace, labelSelector)

	diff := cmp.Diff(&targetPod.Spec, &preflightPod.Spec,
		cmpopts.IgnoreFields(corev1.PodSpec{}, DefaultPreflightPodSpecDriftIgnore...),
		cmpopts.EquateEmpty(),
	)
	require.Empty(t, diff, "preflight pod %s/%s drifted from target %s/%s:\n%s",
		preflightPod.Namespace, preflightPod.Name, targetPod.Namespace, targetPod.Name, diff)
}

// findAnyOperandPod returns any Running pod matching labelSelector.
// Which replica is fine: control-plane operand PodSpecs should match across replicas for fields we compare.
func findAnyOperandPod(ctx context.Context, t testing.TB, clientSet ClientSet, namespace, labelSelector string) *corev1.Pod {
	t.Helper()
	pods, err := clientSet.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	require.NoError(t, err)
	for i := range pods.Items {
		if pods.Items[i].Status.Phase == corev1.PodRunning {
			return &pods.Items[i]
		}
	}
	return nil
}
