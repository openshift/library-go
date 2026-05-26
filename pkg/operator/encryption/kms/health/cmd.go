package health

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

const providerName = "kms-health-monitor"

type commandOptions struct {
	kmsSockets     []string
	readInterval   time.Duration
	readTimeout    time.Duration
	writeTimeout   time.Duration
	targetOperator string
	nodeName       string
	kubeconfig     string
}

func NewCommand(ctx context.Context) *cobra.Command {
	o := &commandOptions{
		readInterval: 30 * time.Second,
		readTimeout:  5 * time.Second,
		writeTimeout: 10 * time.Second,
	}
	cmd := &cobra.Command{
		Use:   "kms-health-monitor",
		Short: "Observes a co-located KMSv2 plugin and publishes status as an OperatorCondition.",
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

func (o *commandOptions) addFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&o.kmsSockets, "kms-sockets", nil, "filesystem paths to the KMSv2 plugin UDS")
	fs.DurationVar(&o.readInterval, "read-interval", o.readInterval, "cadence between checks")
	fs.DurationVar(&o.readTimeout, "read-timeout", o.readTimeout, "deadline for each Status RPC")
	fs.DurationVar(&o.writeTimeout, "write-timeout", o.writeTimeout, "deadline for each condition update; should fit inside --read-interval")
	fs.StringVar(&o.targetOperator, "target-operator", "", "target operator CRD: "+strings.Join(supportedOperatorKeys(), ", "))
	fs.StringVar(&o.nodeName, "node-name", "", "node name recorded in the condition used to help to identify the origin")
	fs.StringVar(&o.kubeconfig, "kubeconfig", "", "path to a kubeconfig; empty uses in-cluster config")
}

func (o *commandOptions) validate() error {
	if len(o.kmsSockets) == 0 {
		return fmt.Errorf("--kms-sockets is required, at least one")
	}
	if o.readInterval <= 0 {
		return fmt.Errorf("--read-interval must be positive")
	}
	if o.readTimeout <= 0 {
		return fmt.Errorf("--read-timeout must be positive")
	}
	if o.writeTimeout <= 0 {
		return fmt.Errorf("--write-timeout must be positive")
	}
	if o.nodeName == "" {
		return fmt.Errorf("--node-name is required")
	}
	if _, ok := supportedOperators[TargetOperator(o.targetOperator)]; !ok {
		return fmt.Errorf("--target-operator must be one of %s (got %q)",
			strings.Join(supportedOperatorKeys(), ", "), o.targetOperator)
	}
	return nil
}

func (o *commandOptions) run(ctx context.Context) error {
	cfg, err := buildRESTConfig(o.kubeconfig)
	if err != nil {
		return fmt.Errorf("build rest config: %w", err)
	}
	_, err = buildWriter(cfg, TargetOperator(o.targetOperator))
	if err != nil {
		return fmt.Errorf("create new writer: %w", err)
	}

	_, err = NewChecker(ctx, o.kmsSockets, o.readTimeout)
	if err != nil {
		return fmt.Errorf("create new checker: %w", err)
	}

	klog.InfoS("kms-health-monitor starting",
		"socket", o.kmsSockets,
		"targetOperator", o.targetOperator,
		"observerNode", o.nodeName,
		"interval", o.readInterval,
		"readTimeout", o.readTimeout,
		"writeTimeout", o.writeTimeout,
	)

	return nil
}

func buildRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}
