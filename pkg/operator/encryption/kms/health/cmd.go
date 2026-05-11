package health

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/operator/genericoperatorclient"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8senvelopekmsv2 "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/kmsv2"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

const providerName = "kms-health-monitor"

var supportedOperators = map[string]struct {
	GVR schema.GroupVersionResource
	GVK schema.GroupVersionKind
}{
	"kubeapiserver": {
		GVR: schema.GroupVersionResource{Group: "operator.openshift.io", Version: "v1", Resource: "kubeapiservers"},
		GVK: schema.GroupVersionKind{Group: "operator.openshift.io", Version: "v1", Kind: "KubeAPIServer"},
	},
	"authentication": {
		GVR: schema.GroupVersionResource{Group: "operator.openshift.io", Version: "v1", Resource: "authentications"},
		GVK: schema.GroupVersionKind{Group: "operator.openshift.io", Version: "v1", Kind: "Authentication"},
	},
	"openshiftapiserver": {
		GVR: schema.GroupVersionResource{Group: "operator.openshift.io", Version: "v1", Resource: "openshiftapiservers"},
		GVK: schema.GroupVersionKind{Group: "operator.openshift.io", Version: "v1", Kind: "OpenShiftAPIServer"},
	},
}

type commandOptions struct {
	kmsSocket        string
	probeInterval    time.Duration
	probeTimeout     time.Duration
	writeTimeout     time.Duration
	operatorResource string
	observerPodName  string
	kubeconfig       string
}

// NewCommand wires the cobra command. ctx is owned by the caller so
// signal handling lives there, not here.
func NewCommand(ctx context.Context) *cobra.Command {
	o := &commandOptions{
		kmsSocket:     "/var/run/kmsplugin/kms.sock",
		probeInterval: 60 * time.Second,
		probeTimeout:  3 * time.Second,
		writeTimeout:  5 * time.Second,
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
	fs.StringVar(&o.kmsSocket, "kms-socket", o.kmsSocket, "filesystem path to the KMSv2 plugin UDS")
	fs.DurationVar(&o.probeInterval, "probe-interval", o.probeInterval, "cadence between probes")
	fs.DurationVar(&o.probeTimeout, "probe-timeout", o.probeTimeout, "deadline for each Status RPC")
	fs.DurationVar(&o.writeTimeout, "write-timeout", o.writeTimeout, "deadline for each condition update; should fit inside --probe-interval")
	fs.StringVar(&o.operatorResource, "operator-resource", o.operatorResource,
		"target operator CRD: "+strings.Join(supportedOperatorKeys(), ", "))
	fs.StringVar(&o.observerPodName, "observer-pod-name", os.Getenv("POD_NAME"),
		"pod name recorded in the condition; defaults to $POD_NAME")
	fs.StringVar(&o.kubeconfig, "kubeconfig", "", "path to a kubeconfig; empty uses in-cluster config")
}

func (o *commandOptions) validate() error {
	if o.kmsSocket == "" {
		return fmt.Errorf("--kms-socket is required")
	}
	if o.probeInterval <= 0 {
		return fmt.Errorf("--probe-interval must be positive")
	}
	if o.probeTimeout <= 0 {
		return fmt.Errorf("--probe-timeout must be positive")
	}
	if o.writeTimeout <= 0 {
		return fmt.Errorf("--write-timeout must be positive")
	}
	if o.observerPodName == "" {
		return fmt.Errorf("--observer-pod-name is required (or set $POD_NAME)")
	}
	if _, ok := supportedOperators[o.operatorResource]; !ok {
		return fmt.Errorf("--operator-resource must be one of %s (got %q)",
			strings.Join(supportedOperatorKeys(), ", "), o.operatorResource)
	}
	return nil
}

func (o *commandOptions) run(ctx context.Context) error {
	cfg, err := buildRESTConfig(o.kubeconfig)
	if err != nil {
		return fmt.Errorf("build rest config: %w", err)
	}

	target := supportedOperators[o.operatorResource]
	operatorClient, _, err := genericoperatorclient.NewClusterScopedOperatorClient(
		clock.RealClock{}, cfg, target.GVR, target.GVK,
		emptyOperatorSpec, emptyOperatorStatus,
	)
	if err != nil {
		return fmt.Errorf("build operator client for %s: %w", o.operatorResource, err)
	}
	writer := NewOperatorConditionWriter(operatorClient, o.observerPodName)

	// kmsv2.NewGRPCService sets WaitForReady(true), so dial returns
	// immediately even if the plugin socket isn't listening yet.
	endpoint := "unix://" + o.kmsSocket
	service, err := k8senvelopekmsv2.NewGRPCService(ctx, endpoint, providerName, o.probeTimeout)
	if err != nil {
		return fmt.Errorf("dial KMS plugin at %q: %w", endpoint, err)
	}
	probe := NewProbe(service, 0)

	monitor := NewMonitor(probe, writer, o.observerPodName, o.probeInterval, o.writeTimeout)

	klog.InfoS("kms-health-monitor starting",
		"socket", o.kmsSocket,
		"operatorResource", o.operatorResource,
		"observerPod", o.observerPodName,
		"interval", o.probeInterval,
		"probeTimeout", o.probeTimeout,
		"writeTimeout", o.writeTimeout,
	)

	monitor.Run(ctx)
	klog.Info("kms-health-monitor stopping")
	return nil
}

func buildRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func supportedOperatorKeys() []string {
	keys := make([]string, 0, len(supportedOperators))
	for k := range supportedOperators {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Empty extractors are sufficient: OperatorConditionWriter reads prior
// conditions via GetOperatorState (which does not use these) and writes
// via SSA with its own fieldManager.
func emptyOperatorSpec(_ *unstructured.Unstructured, _ string) (*applyoperatorv1.OperatorSpecApplyConfiguration, error) {
	return applyoperatorv1.OperatorSpec(), nil
}

func emptyOperatorStatus(_ *unstructured.Unstructured, _ string) (*applyoperatorv1.OperatorStatusApplyConfiguration, error) {
	return applyoperatorv1.OperatorStatus(), nil
}
