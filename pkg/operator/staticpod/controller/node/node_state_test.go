package node

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetNodeUpgradeState(t *testing.T) {
	tests := []struct {
		name        string
		node        *corev1.Node
		wantStatus  NodeUpgradeState
		description string
	}{
		{
			name: "node with Done state",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState: machineConfigStateDone,
					},
				},
			},
			wantStatus:  NodeUpgradeStateDone,
			description: "Node has successfully completed update",
		},
		{
			name: "node with Working state - basic",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState: machineConfigStateWorking,
					},
				},
			},
			wantStatus:  NodeUpgradeStateWorking,
			description: "Node is applying configuration changes",
		},
		{
			name: "node with Working state - rebooting",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState:            machineConfigStateWorking,
						machineConfigPostConfigAction: machineConfigPostConfigActionRebooting,
					},
				},
			},
			wantStatus:  NodeUpgradeStateRebooting,
			description: "Node is rebooting or queued for reboot",
		},
		{
			name: "node with Working state - draining in progress",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState:            machineConfigStateWorking,
						machineConfigDesiredDrain:     "drain-rendered-worker-xyz789",
						machineConfigLastAppliedDrain: "drain-rendered-worker-abc123",
					},
				},
			},
			wantStatus:  NodeUpgradeStateDraining,
			description: "Node is being drained (desiredDrain != lastAppliedDrain)",
		},
		{
			name: "node with Working state - draining requested but not started",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState:        machineConfigStateWorking,
						machineConfigDesiredDrain: "drain-rendered-worker-xyz789",
						// lastAppliedDrain is empty/missing
					},
				},
			},
			wantStatus:  NodeUpgradeStateDraining,
			description: "Node drain requested but controller hasn't started yet",
		},
		{
			name: "node with Working state - drain completed",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState:            machineConfigStateWorking,
						machineConfigDesiredDrain:     "drain-rendered-worker-xyz789",
						machineConfigLastAppliedDrain: "drain-rendered-worker-xyz789",
					},
				},
			},
			wantStatus:  NodeUpgradeStateWorking,
			description: "Drain completed (desiredDrain == lastAppliedDrain), node is applying changes",
		},
		{
			name: "node with Working state - no drain needed",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState: machineConfigStateWorking,
						// desiredDrain is empty - no drain needed
					},
				},
			},
			wantStatus:  NodeUpgradeStateWorking,
			description: "No drain required for this update",
		},
		{
			name: "node with Degraded state",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState: machineConfigStateDegraded,
					},
				},
			},
			wantStatus:  NodeUpgradeStateDegraded,
			description: "Node encountered operational errors during update",
		},
		{
			name: "node with Unreconcilable state",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState: machineConfigStateUnreconcilable,
					},
				},
			},
			wantStatus:  NodeUpgradeStateUnreconcilable,
			description: "MachineConfig contains incompatible changes",
		},
		{
			name: "node with nil annotations",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-node",
					Annotations: nil,
				},
			},
			wantStatus:  NodeUpgradeStateUnknown,
			description: "Node has no annotations",
		},
		{
			name: "node with empty annotations",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-node",
					Annotations: map[string]string{},
				},
			},
			wantStatus:  NodeUpgradeStateUnknown,
			description: "Node has annotations but state is missing",
		},
		{
			name: "node with unexpected state value",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState: "UnexpectedState",
					},
				},
			},
			wantStatus:  NodeUpgradeStateUnknown,
			description: "State annotation has unexpected value",
		},
		{
			name: "edge case - empty desiredDrain but old lastAppliedDrain exists",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState:            machineConfigStateWorking,
						machineConfigDesiredDrain:     "", // No drain needed now
						machineConfigLastAppliedDrain: "drain-rendered-worker-old",
					},
				},
			},
			wantStatus:  NodeUpgradeStateWorking,
			description: "Previous drain completed, current update doesn't need drain",
		},
		{
			name: "rebooting takes precedence over drain annotations",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						machineConfigState:            machineConfigStateWorking,
						machineConfigPostConfigAction: machineConfigPostConfigActionRebooting,
						machineConfigDesiredDrain:     "drain-rendered-worker-xyz789",
						machineConfigLastAppliedDrain: "drain-rendered-worker-xyz789",
					},
				},
			},
			wantStatus:  NodeUpgradeStateRebooting,
			description: "Rebooting is checked before draining status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStatus := GetNodeUpgradeState(tt.node)
			if gotStatus != tt.wantStatus {
				t.Errorf("GetNodeUpgradeState() = %v, want %v\nDescription: %s", gotStatus, tt.wantStatus, tt.description)
			}
		})
	}
}
