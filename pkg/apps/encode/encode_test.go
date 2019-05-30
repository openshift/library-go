package encode

import (
	"testing"
	"time"

	appsv1 "github.com/openshift/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/apps/util"
	appstest "github.com/openshift/library-go/pkg/apps/util/test"
)

func TestRolloutExceededTimeoutSeconds(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name                   string
		config                 *appsv1.DeploymentConfig
		deploymentCreationTime time.Time
		expectTimeout          bool
	}{
		// Recreate strategy with deployment running for 20s (exceeding 10s timeout)
		{
			name: "recreate timeout",
			config: func(timeoutSeconds int64) *appsv1.DeploymentConfig {
				config := appstest.OkDeploymentConfig(1)
				config.Spec.Strategy.RecreateParams.TimeoutSeconds = &timeoutSeconds
				return config
			}(int64(10)),
			deploymentCreationTime: now.Add(-20 * time.Second),
			expectTimeout:          true,
		},
		// Recreate strategy with no timeout
		{
			name: "recreate no timeout",
			config: func(timeoutSeconds int64) *appsv1.DeploymentConfig {
				config := appstest.OkDeploymentConfig(1)
				config.Spec.Strategy.RecreateParams.TimeoutSeconds = &timeoutSeconds
				return config
			}(int64(0)),
			deploymentCreationTime: now.Add(-700 * time.Second),
			expectTimeout:          false,
		},

		// Rolling strategy with deployment running for 20s (exceeding 10s timeout)
		{
			name: "rolling timeout",
			config: func(timeoutSeconds int64) *appsv1.DeploymentConfig {
				config := appstest.OkDeploymentConfig(1)
				config.Spec.Strategy = appstest.OkRollingStrategy()
				config.Spec.Strategy.RollingParams.TimeoutSeconds = &timeoutSeconds
				return config
			}(int64(10)),
			deploymentCreationTime: now.Add(-20 * time.Second),
			expectTimeout:          true,
		},
		// Rolling strategy with deployment with no timeout specified.
		{
			name: "rolling using default timeout",
			config: func(timeoutSeconds int64) *appsv1.DeploymentConfig {
				config := appstest.OkDeploymentConfig(1)
				config.Spec.Strategy = appstest.OkRollingStrategy()
				config.Spec.Strategy.RollingParams.TimeoutSeconds = nil
				return config
			}(0),
			deploymentCreationTime: now.Add(-20 * time.Second),
			expectTimeout:          false,
		},
		// Recreate strategy with deployment with no timeout specified.
		{
			name: "recreate using default timeout",
			config: func(timeoutSeconds int64) *appsv1.DeploymentConfig {
				config := appstest.OkDeploymentConfig(1)
				config.Spec.Strategy.RecreateParams.TimeoutSeconds = nil
				return config
			}(0),
			deploymentCreationTime: now.Add(-20 * time.Second),
			expectTimeout:          false,
		},
		// Custom strategy with deployment with no timeout specified.
		{
			name: "custom using default timeout",
			config: func(timeoutSeconds int64) *appsv1.DeploymentConfig {
				config := appstest.OkDeploymentConfig(1)
				config.Spec.Strategy = appstest.OkCustomStrategy()
				return config
			}(0),
			deploymentCreationTime: now.Add(-20 * time.Second),
			expectTimeout:          false,
		},
		// Custom strategy use default timeout exceeding it.
		{
			name: "custom using default timeout timing out",
			config: func(timeoutSeconds int64) *appsv1.DeploymentConfig {
				config := appstest.OkDeploymentConfig(1)
				config.Spec.Strategy = appstest.OkCustomStrategy()
				return config
			}(0),
			deploymentCreationTime: now.Add(-700 * time.Second),
			expectTimeout:          true,
		},
	}

	for _, tc := range tests {
		config := tc.config
		deployment, err := MakeDeployment(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		deployment.ObjectMeta.CreationTimestamp = metav1.Time{Time: tc.deploymentCreationTime}
		gotTimeout := util.RolloutExceededTimeoutSeconds(config, deployment)
		if tc.expectTimeout && !gotTimeout {
			t.Errorf("[%s]: expected timeout, but got no timeout", tc.name)
		}
		if !tc.expectTimeout && gotTimeout {
			t.Errorf("[%s]: expected no timeout, but got timeout", tc.name)
		}

	}
}
