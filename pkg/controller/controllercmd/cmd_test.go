package controllercmd

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/config/client"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/utils/clock"
)

func TestControllerCommandConfig_WithKubeConfigOverrides(t *testing.T) {
	overrides := client.ClientConnectionOverrides{
		ClientConnectionOverrides: configv1.ClientConnectionOverrides{
			QPS: 1.0,
		},
	}

	builder := NewControllerCommandConfig("controller", version.Info{}, nil, clock.RealClock{}).
		WithKubeConfigOverrides(&overrides).
		initBuilder()

	if !cmp.Equal(builder.clientOverrides, &overrides) {
		t.Errorf("Kube config overrides mismatch: \n%s", cmp.Diff(&overrides, builder.clientOverrides))
	}
}
