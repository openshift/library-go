package node

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// NodeUpgradeState represents the current state of a node's Machine Config Operator upgrade.
type NodeUpgradeState string

const (
	// NodeUpgradeStateWorking indicates the node is actively applying configuration changes.
	// This state is set when the Machine Config Daemon is updating files, applying OS changes,
	// or performing other non-disruptive update operations.
	NodeUpgradeStateWorking NodeUpgradeState = "Working"

	// NodeUpgradeStateUnreconcilable indicates the desired MachineConfig contains changes
	// that cannot be applied in-place to a running node (e.g., FIPS mode changes, incompatible
	// storage configurations). Manual intervention or reinstallation is required.
	NodeUpgradeStateUnreconcilable NodeUpgradeState = "Unreconcilable"

	// NodeUpgradeStateDraining indicates the node is being cordoned and drained of workloads
	// in preparation for disruptive changes (typically a reboot).
	NodeUpgradeStateDraining NodeUpgradeState = "Draining"

	// NodeUpgradeStateRebooting indicates the node is rebooting or queued for reboot to
	// complete the configuration update.
	NodeUpgradeStateRebooting NodeUpgradeState = "Rebooting"

	// NodeUpgradeStateDegraded indicates an operational error occurred during the update
	// (e.g., service restart failures, validation failures, timeouts). The MachineConfig
	// itself is valid, but environmental or operational issues prevent applying it.
	NodeUpgradeStateDegraded NodeUpgradeState = "Degraded"

	// NodeUpgradeStateDone indicates the node has successfully completed the update and
	// the current configuration matches the desired configuration.
	NodeUpgradeStateDone NodeUpgradeState = "Done"

	// NodeUpgradeStateUnknown indicates the node's upgrade status cannot be determined,
	// either because annotations are missing or the state has an unexpected value.
	NodeUpgradeStateUnknown NodeUpgradeState = "Unknown"
)

// Machine Config Operator node annotation keys and values.
const (
	// machineConfigState is the annotation key for the current state of the Machine Config Daemon.
	machineConfigState = "machineconfiguration.openshift.io/state"

	// machineConfigDesiredDrain is the annotation key set by the daemon to request node drain.
	machineConfigDesiredDrain = "machineconfiguration.openshift.io/desiredDrain"

	// machineConfigLastAppliedDrain is the annotation key set by the drain controller to indicate
	// the last drain request that was successfully applied.
	machineConfigLastAppliedDrain = "machineconfiguration.openshift.io/lastAppliedDrain"

	// machineConfigPostConfigAction is the annotation key for post-configuration actions,
	// such as indicating a reboot is queued or in progress.
	machineConfigPostConfigAction = "machineconfiguration.openshift.io/post-config-action"

	// machineConfigStateDone indicates the daemon has successfully completed an update.
	machineConfigStateDone = "Done"

	// machineConfigStateWorking indicates the daemon is actively applying an update.
	machineConfigStateWorking = "Working"

	// machineConfigStateDegraded indicates an operational error occurred during the update.
	machineConfigStateDegraded = "Degraded"

	// machineConfigStateUnreconcilable indicates the MachineConfig contains incompatible changes.
	machineConfigStateUnreconcilable = "Unreconcilable"

	// machineConfigPostConfigActionRebooting indicates a reboot is queued or in progress.
	machineConfigPostConfigActionRebooting = "Rebooting"
)

// GetNodeUpgradeState returns the current upgrade status of a node based on
// Machine Config Operator annotations.
//
// The function examines the node's MCO annotations to determine the upgrade state.
// When the state annotation is "Working", it further distinguishes between different
// phases of the update process:
//   - Rebooting: node is rebooting or queued for reboot (post-config-action == "Rebooting")
//   - Draining: node is being cordoned and drained (desiredDrain != lastAppliedDrain)
//   - Working: node is applying configuration changes (default "Working" state)
//
// Returns NodeUpgradeStateUnknown if the node has no annotations or the state
// annotation has an unexpected value.
func GetNodeUpgradeState(node *corev1.Node) NodeUpgradeState {
	if node.Annotations == nil {
		return NodeUpgradeStateUnknown
	}

	switch node.Annotations[machineConfigState] {
	case machineConfigStateDone:
		return NodeUpgradeStateDone

	case machineConfigStateWorking:
		if node.Annotations[machineConfigPostConfigAction] == machineConfigPostConfigActionRebooting {
			return NodeUpgradeStateRebooting
		}

		desiredDrain := node.Annotations[machineConfigDesiredDrain]
		lastAppliedDrain := node.Annotations[machineConfigLastAppliedDrain]
		// The desired action is not always "drain". We need to check the action prefix.
		if strings.HasPrefix(desiredDrain, "drain-") && lastAppliedDrain != desiredDrain {
			return NodeUpgradeStateDraining
		}

		return NodeUpgradeStateWorking

	case machineConfigStateDegraded:
		return NodeUpgradeStateDegraded

	case machineConfigStateUnreconcilable:
		return NodeUpgradeStateUnreconcilable

	default:
		return NodeUpgradeStateUnknown
	}
}
