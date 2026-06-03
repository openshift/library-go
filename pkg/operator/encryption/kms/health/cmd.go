package health

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

type options struct {
	kmsSockets     []string
	readInterval   time.Duration
	readTimeout    time.Duration
	writeTimeout   time.Duration
	targetGroup    string
	targetVersion  string
	targetResource string
	targetKind     string
	nodeName       string
}

func NewCommand(ctx context.Context) *cobra.Command {
	o := &options{
		readInterval: 30 * time.Second,
		readTimeout:  5 * time.Second,
		writeTimeout: 10 * time.Second,
	}

	startFunc := func(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
		if err := o.validate(); err != nil {
			return err
		}
		return o.run(ctx, controllerContext.KubeConfig)
	}

	cfg := controllercmd.NewControllerCommandConfig(
		"kms-health-monitor",
		version.Info{Major: "0", Minor: "0"},
		startFunc,
		clock.RealClock{},
	)
	cfg.DisableLeaderElection = true
	cfg.DisableServing = true

	cmd := cfg.NewCommandWithContext(ctx)
	cmd.Use = "kms-health-monitor"
	cmd.Short = "Observes co-located KMSv2 plugins and publishes status as an OperatorCondition."

	o.addFlags(cmd.Flags())
	return cmd
}

func (o *options) addFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&o.kmsSockets, "kms-sockets", nil, "KMS plugin endpoints in unix:// URI format (e.g. unix:///var/run/kmsplugin/kms-1.sock)")
	fs.DurationVar(&o.readInterval, "read-interval", o.readInterval, "cadence between checks")
	fs.DurationVar(&o.readTimeout, "read-timeout", o.readTimeout, "deadline for each Status RPC")
	fs.DurationVar(&o.writeTimeout, "write-timeout", o.writeTimeout, "deadline for each condition update")
	fs.StringVar(&o.targetGroup, "target-group", "", "API group of the operator CR (e.g. operator.openshift.io)")
	fs.StringVar(&o.targetVersion, "target-version", "v1", "API version of the operator CR")
	fs.StringVar(&o.targetResource, "target-resource", "", "resource name of the operator CR (e.g. kubeapiservers)")
	fs.StringVar(&o.targetKind, "target-kind", "", "kind of the operator CR (e.g. KubeAPIServer)")
	fs.StringVar(&o.nodeName, "node-name", "", "node name recorded in the condition to identify the origin")
}

func (o *options) validate() error {
	if len(o.kmsSockets) == 0 {
		return fmt.Errorf("--kms-sockets is required, at least one")
	}
	for _, s := range o.kmsSockets {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("--kms-sockets cannot contain empty entries")
		}
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
	if o.targetGroup == "" {
		return fmt.Errorf("--target-group is required")
	}
	if o.targetResource == "" {
		return fmt.Errorf("--target-resource is required")
	}
	if o.targetKind == "" {
		return fmt.Errorf("--target-kind is required")
	}
	return nil
}

func (o *options) run(ctx context.Context, restConfig *rest.Config) error {
	gvr := schema.GroupVersionResource{Group: o.targetGroup, Version: o.targetVersion, Resource: o.targetResource}
	gvk := schema.GroupVersionKind{Group: o.targetGroup, Version: o.targetVersion, Kind: o.targetKind}

	klog.InfoS("kms-health-monitor starting",
		"sockets", o.kmsSockets,
		"target", gvr.String(),
		"observerNode", o.nodeName,
		"interval", o.readInterval,
		"readTimeout", o.readTimeout,
		"writeTimeout", o.writeTimeout,
	)

	writer, err := newWriter(restConfig, gvr, gvk, o.nodeName)
	if err != nil {
		return fmt.Errorf("create writer: %w", err)
	}
	checker, err := NewChecker(ctx, o.kmsSockets, o.readTimeout)
	if err != nil {
		return fmt.Errorf("create checker: %w", err)
	}

	wait.JitterUntilWithContext(ctx, func(ctx context.Context) {
		probeCtx, cancel := context.WithTimeout(ctx, o.readTimeout)
		defer cancel()
		conditions := checker.CheckStatus(probeCtx)

		writeCtx, writeCancel := context.WithTimeout(ctx, o.writeTimeout)
		defer writeCancel()
		if err := writer.Apply(writeCtx, conditions); err != nil {
			klog.ErrorS(err, "apply operator status")
		}
	}, o.readInterval, 0.1, false)

	return nil
}
