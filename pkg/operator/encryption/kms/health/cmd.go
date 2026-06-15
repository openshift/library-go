package health

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server"
	k8senvelopekmsv2 "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/kmsv2"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

const providerName = "kms-health-reporter"

// kmsSocketPattern matches the socket path each co-located KMSv2 plugin is
// mounted at, e.g. unix:///var/run/kmsplugin/kms-1.sock.
var kmsSocketPattern = regexp.MustCompile(`^unix:///var/run/kmsplugin/kms-(\d+)\.sock$`)

// keyIDFromSocket extracts the sequential key id captured by kmsSocketPattern,
// e.g. "1" from unix:///var/run/kmsplugin/kms-1.sock.
func keyIDFromSocket(socket string) (string, error) {
	m := kmsSocketPattern.FindStringSubmatch(socket)
	if m == nil {
		return "", fmt.Errorf("socket %q must match %s", socket, kmsSocketPattern)
	}
	return m[1], nil
}

// options' flag-bound fields are exported so the struct can be logged as a
// whole via klog.InfoS, which JSON-marshals its values.
type options struct {
	KMSSockets   []string
	Interval     time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	NodeName     string
	Kubeconfig   string

	newOperatorClient func(*rest.Config) (v1helpers.OperatorClient, error)
}

func NewCommand(ctx context.Context, newOperatorClient func(*rest.Config) (v1helpers.OperatorClient, error)) *cobra.Command {
	o := &options{
		newOperatorClient: newOperatorClient,
	}

	cmd := &cobra.Command{
		Use:   "kms-health-reporter",
		Short: "Observes co-located KMSv2 plugins and publishes status as an OperatorCondition.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			return o.run(ctx)
		},
	}
	o.addFlags(cmd.Flags())
	return cmd
}

func (o *options) addFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&o.KMSSockets, "kms-sockets", nil, "KMS plugin endpoints in unix:// URI format (e.g. unix:///var/run/kmsplugin/kms-1.sock)")
	fs.DurationVar(&o.Interval, "interval", 30*time.Second, "cadence between probe+emit cycles")
	fs.DurationVar(&o.ReadTimeout, "read-timeout", 5*time.Second, "deadline for each Status RPC")
	fs.DurationVar(&o.WriteTimeout, "write-timeout", 10*time.Second, "deadline for each condition update")
	fs.StringVar(&o.NodeName, "node-name", "", "node name recorded in the condition used to help to identify the origin")
	fs.StringVar(&o.Kubeconfig, "kubeconfig", "", "path to a kubeconfig; empty uses in-cluster config")
}

func (o *options) validate() error {
	if len(o.KMSSockets) == 0 {
		return fmt.Errorf("--kms-sockets is required, at least one")
	}
	socketSet := sets.New[string]()
	for _, s := range o.KMSSockets {
		if !kmsSocketPattern.MatchString(s) {
			return fmt.Errorf("--kms-sockets entry %q must match %s", s, kmsSocketPattern)
		}
		if socketSet.Has(s) {
			return fmt.Errorf("--kms-sockets entry %q is duplicated", s)
		}
		socketSet.Insert(s)
	}

	if o.Interval <= 0 {
		return fmt.Errorf("--interval must be positive")
	}
	if o.ReadTimeout <= 0 {
		return fmt.Errorf("--read-timeout must be positive")
	}
	if o.WriteTimeout <= 0 {
		return fmt.Errorf("--write-timeout must be positive")
	}
	if o.NodeName == "" {
		return fmt.Errorf("--node-name is required")
	}

	return nil
}

func (o *options) run(ctx context.Context) error {
	ctx = setupSignalContext(ctx)

	// Empty kubeconfig falls back to the in-cluster config (service account
	// token + KUBERNETES_SERVICE_HOST), which is the deployed path.
	cfg, err := clientcmd.BuildConfigFromFlags("", o.Kubeconfig)
	if err != nil {
		return fmt.Errorf("build rest config: %w", err)
	}

	if _, err := o.newOperatorClient(cfg); err != nil {
		return fmt.Errorf("build operator client: %w", err)
	}

	plugins, err := buildPlugins(ctx, o.KMSSockets, o.ReadTimeout)
	if err != nil {
		return err
	}
	prober := newProber(plugins)

	klog.InfoS("kms-health-reporter starting", "config", o)

	wait.JitterUntilWithContext(ctx, func(ctx context.Context) {
		// Each Status RPC enforces o.ReadTimeout internally (set at dial time);
		// ctx here only carries shutdown cancellation.
		conditions := prober.probeAll(ctx)
		// TODO: hand conditions to the writer once it lands; logging is a placeholder.
		klog.InfoS("kms plugin health", "conditions", conditions)
	}, o.Interval, 0.1, false)

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
		service, err := k8senvelopekmsv2.NewGRPCService(ctx, socket, providerName+"-"+keyID, timeout)
		if err != nil {
			// With the current dependency version this should never happen with a validated GRPC endpoint.
			return nil, fmt.Errorf("setting up grpc service failed at %q: %w", socket, err)
		}

		plugins = append(plugins, pluginClient{keyID: keyID, service: service})
	}

	return plugins, nil
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
