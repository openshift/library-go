package featuregates

import (
	"context"

	configv1 "github.com/openshift/api/config/v1"
)

type hardcodedFeatureGateAccess struct {
	enabled  []configv1.FeatureGateName
	disabled []configv1.FeatureGateName
	readErr  error

	initialFeatureGatesObserved               chan struct{}
	featureGatesHaveChangedSinceFirstObserved chan struct{}
}

// NewHardcodedFeatureGateAccess is useful for unit testing, potentially in other packages as well.
func NewHardcodedFeatureGateAccess(enabled, disabled []configv1.FeatureGateName) FeatureGateAccess {
	initialFeatureGatesObserved := make(chan struct{})
	close(initialFeatureGatesObserved)
	c := &hardcodedFeatureGateAccess{
		enabled:                     enabled,
		disabled:                    disabled,
		initialFeatureGatesObserved: initialFeatureGatesObserved,
		featureGatesHaveChangedSinceFirstObserved: make(chan struct{}),
	}

	return c
}

func (c *hardcodedFeatureGateAccess) SetChangeHandler(featureGateChangeHandlerFn FeatureGateChangeHandlerFunc) {
	// ignore
}

func (c *hardcodedFeatureGateAccess) Run(ctx context.Context) {
	// ignore
}

func (c *hardcodedFeatureGateAccess) InitialFeatureGatesObserved() chan struct{} {
	return c.initialFeatureGatesObserved
}

func (c *hardcodedFeatureGateAccess) FeatureGatesHaveChangedSinceFirstObserved() chan struct{} {
	return c.featureGatesHaveChangedSinceFirstObserved
}

func (c *hardcodedFeatureGateAccess) AreInitialFeatureGatesObserved() bool {
	select {
	case <-c.InitialFeatureGatesObserved():
		return true
	default:
		return false
	}
}

func (c *hardcodedFeatureGateAccess) CurrentFeatureGates() ([]configv1.FeatureGateName, []configv1.FeatureGateName, error) {
	return c.enabled, c.disabled, c.readErr
}
