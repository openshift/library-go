package manifestclient

import (
	"context"
	"testing"
)

func TestWithControllerNameInContext(t *testing.T) {
	scenarios := []struct {
		name                   string
		ctx                    context.Context
		controllerNameToSet    string
		expectedControllerName string
	}{
		{
			name:                   "controller name is set in ctx",
			ctx:                    context.Background(),
			controllerNameToSet:    "fooController",
			expectedControllerName: "fooController",
		},
		{
			name:                   "empty controller name set in ctx",
			ctx:                    context.Background(),
			controllerNameToSet:    "",
			expectedControllerName: "",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := WithControllerNameInContext(scenario.ctx, scenario.controllerNameToSet)
			retrievedControllerName := ControllerNameFromContext(ctx)
			if retrievedControllerName != scenario.expectedControllerName {
				t.Errorf("expected controller name: %q, got: %q", scenario.expectedControllerName, retrievedControllerName)
			}
		})
	}
}

func TestControllerNameFromContext(t *testing.T) {
	ctx := context.Background()
	retrievedControllerName := ControllerNameFromContext(ctx)
	if len(retrievedControllerName) != 0 {
		t.Errorf("unexpected controller name: %q", retrievedControllerName)
	}
}
