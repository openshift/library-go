package serving

import (
	"crypto/tls"
	"testing"

	"github.com/google/go-cmp/cmp"

	configv1 "github.com/openshift/api/config/v1"
)

func TestToServingOptionsCurvePreferences(t *testing.T) {
	curvePreferences := []int32{int32(tls.X25519), int32(tls.CurveP256)}

	servingOptions, err := ToServingOptions(configv1.HTTPServingInfo{
		ServingInfo: configv1.ServingInfo{
			BindAddress:      "127.0.0.1:8443",
			CurvePreferences: curvePreferences,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(curvePreferences, servingOptions.CurvePreferences); diff != "" {
		t.Errorf("unexpected curve preferences (-want +got):\n%s", diff)
	}
}
