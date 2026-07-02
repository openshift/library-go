package preflight

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	k8senvelopekmsv2 "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/kmsv2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

const kmsSocketEndpoint = "unix:///var/run/kmsplugin/kms.sock"

type options struct {
	kmsCallTimeout time.Duration
	podName        string
	podNamespace   string
	configHash     string
	kubeconfig     string
}

// NewCommand creates the kms-preflight cobra command.
func NewCommand(ctx context.Context) *cobra.Command {
	o := &options{}

	cmd := &cobra.Command{
		Use:   "kms-preflight",
		Short: "Validates that the configured KMS plugin is functional.",
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
	fs.DurationVar(&o.kmsCallTimeout, "kms-call-timeout", 0, "timeout for each gRPC call to the KMS plugin")
	fs.StringVar(&o.configHash, "config-hash", o.configHash, "hash of config to use for encryption")
	fs.StringVar(&o.podName, "pod-name", o.podName, "name of pod to use to report checker status")
	fs.StringVar(&o.podNamespace, "pod-namespace", o.podNamespace, "namespace of pod to report checker status")
	fs.StringVar(&o.kubeconfig, "kubeconfig", o.kubeconfig, "path to a kubeconfig; empty uses in-cluster config")
}

func (o *options) validate() error {
	if o.kmsCallTimeout <= 0 {
		return fmt.Errorf("--kms-call-timeout must be greater than 0")
	}
	if o.configHash == "" {
		return fmt.Errorf("--config-hash is required")
	}
	if o.podName == "" {
		return fmt.Errorf("--pod-name is required")
	}
	if o.podNamespace == "" {
		return fmt.Errorf("--pod-namespace is required")
	}

	return nil
}

func (o *options) run(ctx context.Context) error {
	klog.Infof("Running KMS preflight check at %s", kmsSocketEndpoint)

	// k8senvelopekmsv2.NewGRPCService is not a public API and may change.
	// If it breaks, we can inline a minimal gRPC client using k8s.io/kms directly.
	service, err := k8senvelopekmsv2.NewGRPCService(ctx, kmsSocketEndpoint, "preflight", o.kmsCallTimeout)
	if err != nil {
		return fmt.Errorf("failed to create KMS gRPC client: %w", err)
	}

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", o.kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubeconfig: %w", err)
	}
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("failed to create kube client: %w", err)
	}

	checker := newChecker(service)
	start := time.Now()
	status, checkErr := checker.check(ctx)

	podClient := kubeClient.CoreV1().Pods(o.podNamespace)
	reportErr := setPodCheckCondition(ctx, podClient, o.podName, o.configHash, status, checkErr)
	// join the errors to not lose the original error message
	if err := errors.Join(checkErr, reportErr); err != nil {
		return err
	}

	klog.Infof("KMS preflight check passed, total latency=%v", time.Since(start))
	return nil
}
