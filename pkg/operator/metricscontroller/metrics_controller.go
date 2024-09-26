package metricscontroller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	prometheusapi "github.com/prometheus/client_golang/api"
	prometheusv1 "github.com/prometheus/client_golang/api/prometheus/v1"

	"k8s.io/client-go/transport"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// MetricsSyncFunc is used to set the controller synchronization function for metrics controller.
// It includes the prometheus client.
type MetricsSyncFunc func(ctx context.Context, controllerContext factory.SyncContext, promClient prometheusv1.API) error

type metricsController struct {
	operatorClient          v1helpers.OperatorClient
	prometheusQuery         string
	newPrometheusClientFunc func() (prometheusv1.API, idleConnectionCloser, error)
	metricsSyncFunc         MetricsSyncFunc
	recorder                events.Recorder
}

// NewMetricsController creates a new metrics controller for the given name using an in-cluster prometheus client.
// The given service CA path will be used to read out the CA bundle being trusted by the prometheus client.
// The controller executes the given metrics sync function every minute.
func NewMetricsController(name string, operatorClient v1helpers.OperatorClient, recorder events.Recorder, serviceCAPath string, metricsSyncFunc MetricsSyncFunc) factory.Controller {
	c := &metricsController{
		operatorClient: operatorClient,
		newPrometheusClientFunc: func() (prometheusv1.API, idleConnectionCloser, error) {
			return newInClusterPrometheusClient(serviceCAPath)
		},
		metricsSyncFunc: metricsSyncFunc,
		recorder:        recorder,
	}

	return factory.New().
		WithSync(c.sync).
		ResyncEvery(time.Minute).
		ToController(
			name, // don't change what is passed here unless you also remove the old FooDegraded condition
			recorder,
		)
}

func (c *metricsController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	client, closer, err := c.newPrometheusClientFunc()
	if err != nil {
		err = fmt.Errorf("error instantiating prometheus client: %w", err)
		c.recorder.Warning("PrometheusClientFailed", err.Error())
		return err
	}
	// if idle connections won't be closed, memory leaks will occur.
	defer closer.CloseIdleConnections()
	return c.metricsSyncFunc(ctx, syncCtx, client)
}

type idleConnectionCloser interface {
	CloseIdleConnections()
}

func newInClusterPrometheusClient(serviceCAPath string) (prometheusv1.API, idleConnectionCloser, error) {
	serviceCABytes, err := os.ReadFile(serviceCAPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading service CA: %w", err)
	}

	httpTransport, err := newTransport(serviceCABytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error instantiating prometheus client transport: %w", err)
	}

	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, nil, fmt.Errorf("error reading service account token: %w", err)
	}

	client, err := prometheusapi.NewClient(prometheusapi.Config{
		Address: "https://" + net.JoinHostPort("thanos-querier.openshift-monitoring.svc", "9091"),
		RoundTripper: transport.NewBearerAuthRoundTripper(
			string(saToken),
			httpTransport,
		),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error creating prometheus client: %w", err)
	}

	return prometheusv1.NewAPI(client), httpTransport, nil
}

func newTransport(serviceCABytes []byte) (*http.Transport, error) {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(serviceCABytes)

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
		},
	}, nil
}
