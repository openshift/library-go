package health

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

// kmsSocketPattern matches the socket path each co-located KMSv2 plugin is
// mounted at, e.g. unix:///var/run/kmsplugin/kms-1.sock.
var kmsSocketPattern = regexp.MustCompile(`^unix:///var/run/kmsplugin/kms-\d+\.sock$`)

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
			return o.run()
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
	for _, s := range o.KMSSockets {
		if !kmsSocketPattern.MatchString(s) {
			return fmt.Errorf("--kms-sockets entry %q must match %s", s, kmsSocketPattern)
		}
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

func (o *options) run() error {
	cfg, err := buildRESTConfig(o.Kubeconfig)
	if err != nil {
		return fmt.Errorf("build rest config: %w", err)
	}

	if _, err := o.newOperatorClient(cfg); err != nil {
		return fmt.Errorf("build operator client: %w", err)
	}

	klog.InfoS("kms-health-reporter starting", "config", o)

	return nil
}

func buildRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}
