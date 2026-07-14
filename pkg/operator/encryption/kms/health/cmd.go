package health

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/spf13/cobra"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server"
	k8senvelopekmsv2 "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/kmsv2"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/encryptionstatus"
)

const (
	Subcommand = "kms-health-reporter"
)

// kmsSocketPattern matches the socket path each co-located KMSv2 plugin is
// mounted at, e.g. unix:///var/run/kmsplugin/kms-1.sock.
var kmsSocketPattern = regexp.MustCompile(`^unix:///var/run/kmsplugin/kms-(\d+)\.sock$`)

// NewKMSEncryptionStatusClientFunc builds the KMSEncryptionStatusClient for a
// target apiserver operator status CR. The factory lets sidecar binaries defer
// REST client creation until startup when the in-cluster config is available.
type NewKMSEncryptionStatusClientFunc func(restConfig *rest.Config) (encryptionstatus.KMSEncryptionStatusClient, error)

type Config struct {
	statusClient encryptionstatus.KMSEncryptionStatusClient
	prober       *prober

	fieldManager string
	interval     time.Duration
	writeTimeout time.Duration
}

func NewCommand(ctx context.Context, newClient NewKMSEncryptionStatusClientFunc) *cobra.Command {
	o := &options{
		newClient: newClient,
	}

	cmd := &cobra.Command{
		Use:   Subcommand,
		Short: "Observes co-located KMSv2 plugins and publishes status as an OperatorCondition.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}

			// Arm signal handling before Config builds anything needing graceful teardown.
			// Idiomatically the caller's main would own this; kept here because
			// library-go ships the command, not the main.
			ctx := setupSignalContext(ctx)
			klog.InfoS("kms-health-reporter starting", "config", o)

			cfg, err := o.Config(ctx)
			if err != nil {
				return err
			}
			return cfg.Run(ctx)
		},
	}
	o.addFlags(cmd.Flags())
	return cmd
}

func (c *Config) Run(ctx context.Context) error {
	wait.JitterUntilWithContext(ctx, func(ctx context.Context) {
		// Each Status RPC enforces the read timeout internally (set at dial
		// time); ctx here only carries shutdown cancellation.
		reports := c.prober.probeAll(ctx)

		writeCtx, cancel := context.WithTimeout(ctx, c.writeTimeout)
		defer cancel()
		if err := c.statusClient.ApplyKMSEncryptionStatus(writeCtx, c.fieldManager, reports); err != nil {
			klog.ErrorS(err, "failed to publish kms plugin health")
		}
	}, c.interval, 0.1, false)

	return nil
}

func buildPlugins(ctx context.Context, sockets []string, timeout time.Duration) ([]pluginClient, error) {
	plugins := make([]pluginClient, 0, len(sockets))

	for _, socket := range sockets {
		keyID, err := keyIDFromSocket(socket)
		if err != nil {
			return nil, err
		}

		// Unique name per plugin so the gRPC client's KMS operation metrics
		// don't merge both plugins into one series.
		service, err := k8senvelopekmsv2.NewGRPCService(ctx, socket, Subcommand, timeout)
		if err != nil {
			// With the current dependency version this should never happen with a validated GRPC endpoint.
			return nil, fmt.Errorf("setting up grpc service failed at %q: %w", socket, err)
		}

		plugins = append(plugins, pluginClient{keyID: keyID, service: service})
	}

	return plugins, nil
}

// keyIDFromSocket extracts the sequential key id captured by kmsSocketPattern,
// e.g. "1" from unix:///var/run/kmsplugin/kms-1.sock.
func keyIDFromSocket(socket string) (string, error) {
	m := kmsSocketPattern.FindStringSubmatch(socket)
	if m == nil {
		return "", fmt.Errorf("socket %q must match %s", socket, kmsSocketPattern)
	}
	return m[1], nil
}

// setupSignalContext registers for SIGTERM and SIGINT and returns a context
// that will be cancelled once a signal is received. Compare startupmonitor's
// setupSignalContext.
func setupSignalContext(baseCtx context.Context) context.Context {
	shutdownCtx, cancel := context.WithCancel(baseCtx)
	shutdownHandler := server.SetupSignalHandler()
	go func() {
		defer cancel()
		<-shutdownHandler
		klog.Infof("Received SIGTERM or SIGINT signal, shutting down the process.")
	}()
	return shutdownCtx
}
