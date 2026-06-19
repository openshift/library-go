package health

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildEncryptionStatus(t *testing.T) {
	// Fixed UTC time dodges Go's monotonic clock and timezone drift.
	checked := time.Unix(0, 0).UTC()
	reports := []pluginHealthReport{
		{KeyID: "1", KEKID: "kek-abc", Status: statusHealthy, LastChecked: checked},
		{KeyID: "2", Status: statusUnhealthy, Detail: "not ok", LastChecked: checked},
		{KeyID: "3", Status: statusError, Detail: "DeadlineExceeded", LastChecked: checked},
	}

	have := buildEncryptionStatus("node-1", reports)

	// Each entry stamps nodeName; kekId only on healthy, detail only on the
	// unhealthy/error entries, status mapped to the API enum.
	want := applyoperatorv1.KMSEncryptionStatus().WithHealthReports(
		applyoperatorv1.KMSPluginHealthReport().
			WithNodeName("node-1").
			WithKeyId("1").
			WithStatus(operatorv1.KMSPluginHealthStatusHealthy).
			WithLastCheckedTime(metav1.NewTime(checked)).
			WithKEKId("kek-abc"),
		applyoperatorv1.KMSPluginHealthReport().
			WithNodeName("node-1").
			WithKeyId("2").
			WithStatus(operatorv1.KMSPluginHealthStatusUnhealthy).
			WithLastCheckedTime(metav1.NewTime(checked)).
			WithDetail("not ok"),
		applyoperatorv1.KMSPluginHealthReport().
			WithNodeName("node-1").
			WithKeyId("3").
			WithStatus(operatorv1.KMSPluginHealthStatusError).
			WithLastCheckedTime(metav1.NewTime(checked)).
			WithDetail("DeadlineExceeded"),
	)

	require.Equal(t, want, have)
}

func TestMapStatus(t *testing.T) {
	tests := []struct {
		in   string
		want operatorv1.KMSPluginHealthStatus
	}{
		{statusHealthy, operatorv1.KMSPluginHealthStatusHealthy},
		{statusUnhealthy, operatorv1.KMSPluginHealthStatusUnhealthy},
		{statusError, operatorv1.KMSPluginHealthStatusError},
		{"unexpected", operatorv1.KMSPluginHealthStatusError},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.want, mapStatus(tc.in))
		})
	}
}
