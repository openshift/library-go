// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// ClusterOperatorStatusApplyConfiguration represents a declarative configuration of the ClusterOperatorStatus type for use
// with apply.
type ClusterOperatorStatusApplyConfiguration struct {
	Conditions     []ClusterOperatorStatusConditionApplyConfiguration `json:"conditions,omitempty"`
	Versions       []OperandVersionApplyConfiguration                 `json:"versions,omitempty"`
	RelatedObjects []ObjectReferenceApplyConfiguration                `json:"relatedObjects,omitempty"`
	Extension      *runtime.RawExtension                              `json:"extension,omitempty"`
}

// ClusterOperatorStatusApplyConfiguration constructs a declarative configuration of the ClusterOperatorStatus type for use with
// apply.
func ClusterOperatorStatus() *ClusterOperatorStatusApplyConfiguration {
	return &ClusterOperatorStatusApplyConfiguration{}
}

// WithConditions adds the given value to the Conditions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Conditions field.
func (b *ClusterOperatorStatusApplyConfiguration) WithConditions(values ...*ClusterOperatorStatusConditionApplyConfiguration) *ClusterOperatorStatusApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithConditions")
		}
		b.Conditions = append(b.Conditions, *values[i])
	}
	return b
}

// WithVersions adds the given value to the Versions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Versions field.
func (b *ClusterOperatorStatusApplyConfiguration) WithVersions(values ...*OperandVersionApplyConfiguration) *ClusterOperatorStatusApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithVersions")
		}
		b.Versions = append(b.Versions, *values[i])
	}
	return b
}

// WithRelatedObjects adds the given value to the RelatedObjects field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the RelatedObjects field.
func (b *ClusterOperatorStatusApplyConfiguration) WithRelatedObjects(values ...*ObjectReferenceApplyConfiguration) *ClusterOperatorStatusApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithRelatedObjects")
		}
		b.RelatedObjects = append(b.RelatedObjects, *values[i])
	}
	return b
}

// WithExtension sets the Extension field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Extension field is set to the value of the last call.
func (b *ClusterOperatorStatusApplyConfiguration) WithExtension(value runtime.RawExtension) *ClusterOperatorStatusApplyConfiguration {
	b.Extension = &value
	return b
}
