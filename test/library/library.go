package library

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	WaitPollInterval = time.Second
	WaitPollTimeout  = 10 * time.Minute
)

type LoggingT interface {
	Logf(format string, args ...interface{})
}

// StaticPodOperator identifies a control-plane static pod operator by its
// resource name (the singleton "cluster" instance under operator/v1).
type StaticPodOperator struct {
	Name string
}

// ControlPlaneOperators lists the three static-pod operators that perform
// node-by-node revision rollouts on every OpenShift control-plane change.
var ControlPlaneOperators = []StaticPodOperator{
	{Name: "kube-apiserver"},
	{Name: "kube-controller-manager"},
	{Name: "kube-scheduler"},
}

// WaitForControlPlaneRolloutAll waits for all three control-plane static-pod
// operators to complete a full revision rollout.
//
// For each operator it:
//  1. Records the current LatestAvailableRevision.
//  2. Waits for the operator to publish a higher revision.
//  3. Waits for every node in nodeStatuses to reach LatestAvailableRevision
//     (re-read each poll, so mid-rollout re-revisions are chased automatically).
//  4. Waits for the operator's ClusterOperator to report Available=True,
//     Progressing=False, Degraded=False.
//
// The operators are processed sequentially. ctx should carry the caller's
// deadline; cancel it to abort early.
func WaitForControlPlaneRolloutAll(
	ctx context.Context,
	t LoggingT,
	cfgClient configclient.Interface,
	opClient operatorclient.Interface,
) error {
	for _, op := range ControlPlaneOperators {
		if err := WaitForControlPlaneRollout(ctx, t, cfgClient, opClient, op); err != nil {
			return err
		}
	}
	return nil
}

// WaitForControlPlaneRollout waits for a single static-pod operator to
// complete a full revision rollout (steps 1-4 described on WaitForControlPlaneRolloutAll).
func WaitForControlPlaneRollout(
	ctx context.Context,
	t LoggingT,
	cfgClient configclient.Interface,
	opClient operatorclient.Interface,
	op StaticPodOperator,
) error {
	oldRevision, _, err := getStaticPodRevisionAndNodeStatuses(ctx, opClient, op.Name)
	if err != nil {
		return fmt.Errorf("getting current revision for %s: %w", op.Name, err)
	}
	t.Logf("[%s] at revision %d; waiting for new revision", op.Name, oldRevision)

	newRevision, err := waitForStaticPodRevisionChange(ctx, t, opClient, op.Name, oldRevision)
	if err != nil {
		return fmt.Errorf("waiting for revision change for %s: %w", op.Name, err)
	}
	t.Logf("[%s] published revision %d; waiting for all nodes to adopt it", op.Name, newRevision)

	if err := waitForStaticPodNodeRollout(ctx, t, opClient, op.Name); err != nil {
		return fmt.Errorf("waiting for static pod rollout for %s: %w", op.Name, err)
	}

	if err := WaitForClusterOperatorStable(ctx, t, cfgClient, op.Name); err != nil {
		return fmt.Errorf("waiting for ClusterOperator %s stable: %w", op.Name, err)
	}
	return nil
}

// WaitForClusterOperatorStable polls until the named ClusterOperator reports
// Available=True, Progressing=False, and Degraded=False.
func WaitForClusterOperatorStable(ctx context.Context, t LoggingT, cfgClient configclient.Interface, name string) error {
	return wait.PollUntilContextTimeout(ctx, 10*time.Second, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
		co, err := cfgClient.ConfigV1().ClusterOperators().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Logf("[%s] error getting ClusterOperator: %v", name, err)
			return false, nil
		}
		for _, c := range co.Status.Conditions {
			switch c.Type {
			case "Available":
				if c.Status != "True" {
					t.Logf("[%s] Available=%s: %s", name, c.Status, c.Message)
					return false, nil
				}
			case "Progressing":
				if c.Status != "False" {
					t.Logf("[%s] Progressing=%s: %s", name, c.Status, c.Message)
					return false, nil
				}
			case "Degraded":
				if c.Status != "False" {
					t.Logf("[%s] Degraded=%s: %s", name, c.Status, c.Message)
					return false, nil
				}
			}
		}
		t.Logf("[%s] ClusterOperator stable", name)
		return true, nil
	})
}

// waitForStaticPodRevisionChange polls until LatestAvailableRevision exceeds oldRevision.
func waitForStaticPodRevisionChange(ctx context.Context, t LoggingT, opClient operatorclient.Interface, name string, oldRevision int32) (int32, error) {
	var newRevision int32
	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
		rev, _, err := getStaticPodRevisionAndNodeStatuses(ctx, opClient, name)
		if err != nil {
			t.Logf("[%s] error getting revision: %v", name, err)
			return false, nil
		}
		newRevision = rev
		return rev > oldRevision, nil
	})
	return newRevision, err
}

// waitForStaticPodNodeRollout polls until every node in nodeStatuses has
// currentRevision == LatestAvailableRevision. Both values are re-read each
// poll so mid-rollout re-revisions are chased automatically. Progress is
// logged only when a node's revision changes.
func waitForStaticPodNodeRollout(ctx context.Context, t LoggingT, opClient operatorclient.Interface, name string) error {
	lastSeen := map[string]int32{}
	return wait.PollUntilContextTimeout(ctx, 10*time.Second, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
		latest, nodeStatuses, err := getStaticPodRevisionAndNodeStatuses(ctx, opClient, name)
		if err != nil {
			t.Logf("[%s] error reading operator status: %v", name, err)
			return false, nil
		}
		if len(nodeStatuses) == 0 {
			return false, nil
		}
		allDone := true
		for _, ns := range nodeStatuses {
			if ns.CurrentRevision != latest {
				allDone = false
				if lastSeen[ns.NodeName] != ns.CurrentRevision {
					t.Logf("[%s] node %s: revision %d → %d (target %d)", name, ns.NodeName, lastSeen[ns.NodeName], ns.CurrentRevision, latest)
					lastSeen[ns.NodeName] = ns.CurrentRevision
				}
			}
		}
		if allDone {
			t.Logf("[%s] all nodes at revision %d", name, latest)
		}
		return allDone, nil
	})
}

// getStaticPodRevisionAndNodeStatuses returns LatestAvailableRevision and
// per-node NodeStatuses for the named static-pod operator in a single API call.
func getStaticPodRevisionAndNodeStatuses(ctx context.Context, opClient operatorclient.Interface, name string) (int32, []operatorv1.NodeStatus, error) {
	switch name {
	case "kube-apiserver":
		o, err := opClient.OperatorV1().KubeAPIServers().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			return 0, nil, err
		}
		return o.Status.LatestAvailableRevision, o.Status.NodeStatuses, nil
	case "kube-controller-manager":
		o, err := opClient.OperatorV1().KubeControllerManagers().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			return 0, nil, err
		}
		return o.Status.LatestAvailableRevision, o.Status.NodeStatuses, nil
	case "kube-scheduler":
		o, err := opClient.OperatorV1().KubeSchedulers().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			return 0, nil, err
		}
		return o.Status.LatestAvailableRevision, o.Status.NodeStatuses, nil
	default:
		return 0, nil, fmt.Errorf("unknown static pod operator: %s", name)
	}
}

// GenerateNameForTest generates a name of the form `prefix + test name + random string` that
// can be used as a resource name. Convert the result to lowercase to use as a dns label.
func GenerateNameForTest(t *testing.T, prefix string) string {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	require.NoError(t, err)
	name := []byte(fmt.Sprintf("%s%s-%016x", prefix, t.Name(), n.Int64()))
	// make the name (almost) suitable for use as a dns label
	// only a-z, 0-9, and '-' allowed
	name = regexp.MustCompile("[^a-zA-Z0-9]+").ReplaceAll(name, []byte("-"))
	// collapse multiple `-`
	name = regexp.MustCompile("-+").ReplaceAll(name, []byte("-"))
	// ensure no `-` at beginning or end
	return strings.Trim(string(name), "-")
}
