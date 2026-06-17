package preflight

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	k8senvelopekmsv2 "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/kmsv2"
	"k8s.io/klog/v2"
)

type options struct {
	kmsCallTimeout    time.Duration
	kmsSocketEndpoint string
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
	fs.StringVarP(&o.kmsSocketEndpoint, "endpoint", "e", "", "kms socket endpoint of KMS plugin")
}

func (o *options) validate() error {
	if o.kmsCallTimeout <= 0 {
		return fmt.Errorf("--kms-call-timeout must be greater than 0")
	}

	// parsing the endpoint is taken care of in k8senvelopekmsv2.NewGRPCService below
	if o.kmsSocketEndpoint == "" {
		return fmt.Errorf("--kms-socket-endpoint is required")
	}
	return nil
}

func (o *options) run(ctx context.Context) error {
	klog.Infof("Running KMS preflight check at %s", o.kmsSocketEndpoint)

	// k8senvelopekmsv2.NewGRPCService is not a public API and may change.
	// If it breaks, we can inline a minimal gRPC client using k8s.io/kms directly.
	service, err := k8senvelopekmsv2.NewGRPCService(ctx, o.kmsSocketEndpoint, "preflight", o.kmsCallTimeout)
	if err != nil {
		return fmt.Errorf("failed to create KMS gRPC client: %w", err)
	}

	checker := newChecker(service)
	start := time.Now()
	if err = checker.check(ctx); err != nil {
		return fmt.Errorf("kms preflight check failed: %w", err)
	}

	klog.Infof("KMS preflight check passed, total latency=%v", time.Since(start))
	return nil
}
