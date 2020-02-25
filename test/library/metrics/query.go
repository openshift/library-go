package metrics

import (
	"github.com/openshift/library-go/pkg/metrics/client"
)

// This is left here for compatibility.
// DEPRECATED: use metrics/client.NewPrometheusClient instead
var NewPrometheusClient = client.DeprecatedPrometheusClient
