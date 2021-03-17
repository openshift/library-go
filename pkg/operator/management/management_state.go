package management

import (
	v1 "github.com/openshift/api/operator/v1"
)

var (
	allowOperatorUnmanagedState = true
	allowOperatorRemovedState   = true
)

// These are for unit testing
var (
	getAllowedOperatorUnmanaged = func() bool {
		return allowOperatorUnmanagedState
	}
	getAllowedOperatorRemovedState = func() bool {
		return allowOperatorRemovedState
	}
)

// SetOperatorAlwaysManaged is one time choice when an operator want to opt-out from supporting the "unmanaged" state.
// This is a case of control plane operators or operators that are required to always run otherwise the cluster will
// get into unstable state or critical components will stop working.
func SetOperatorAlwaysManaged() {
	allowOperatorUnmanagedState = false
}

// SetOperatorNotRemovable is one time choice the operator author can make to indicate the operator does not support
// removing of his operand. This makes sense for operators like kube-apiserver where removing operand will lead to a
// bricked, non-automatically recoverable state.
// Unless explicitly set, an operator supports Removed state.
// Note that most library-go controllers do not support Removed state, please check each controller separately.
func SetOperatorNotRemovable() {
	allowOperatorRemovedState = false
}

// IsOperatorAlwaysManaged means the operator can't be set to unmanaged state.
func IsOperatorAlwaysManaged() bool {
	return !getAllowedOperatorUnmanaged()
}

// IsOperatorNotRemovable means the operator can't be set to removed state.
func IsOperatorNotRemovable() bool {
	return !getAllowedOperatorRemovedState()
}

// IsOperatorRemovable means the operator can be set to removed state.
func IsOperatorRemovable() bool {
	return getAllowedOperatorRemovedState()
}

func IsOperatorUnknownState(state v1.ManagementState) bool {
	switch state {
	case v1.Managed, v1.Removed, v1.Unmanaged:
		return false
	default:
		return true
	}
}

// IsOperatorManaged indicates whether the operator management state allows the control loop to proceed and manage the operand.
// Deprecated: use GetSyncAction instead to have better support for Removed state.
func IsOperatorManaged(state v1.ManagementState) bool {
	if IsOperatorAlwaysManaged() || IsOperatorNotRemovable() {
		return true
	}
	switch state {
	case v1.Managed:
		return true
	case v1.Removed:
		return false
	case v1.Unmanaged:
		return false
	}
	return true
}

// SyncAction tells caller of GetSyncAction what to do on operator Sync() based on the management state
type SyncAction string

const (
	// SyncActionManage means the operator should manage its operands (create them if missing, update when needed).
	SyncActionManage = "SyncActionManage"
	// SyncActionDelete means the operator should delete its operands.
	SyncActionDelete = "SyncActionDelete"
	// SyncActionIgnore means the operator should ingore this Sync() call.
	SyncActionIgnore = "SyncActionIgnore"
)

func GetSyncAction(state v1.ManagementState) SyncAction {
	if IsOperatorAlwaysManaged() {
		return SyncActionManage
	}

	switch state {
	case v1.Managed:
		return SyncActionManage
	case v1.Unmanaged:
		return SyncActionIgnore
	case v1.Removed:
		if IsOperatorNotRemovable() {
			return SyncActionManage
		}
		return SyncActionDelete
	}
	return SyncActionManage
}
