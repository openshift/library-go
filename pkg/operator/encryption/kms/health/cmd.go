package health

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	k8senvelopekmsv2 "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/kmsv2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

const (
	outputModeConfigMap = "configmap"
	outputModeCondition = "condition"

	providerName = "kms-health-monitor"
)

type commandOptions struct {
	kmsSocket              string
	probeInterval          time.Duration
	probeIntervalUnhealthy time.Duration
	probeTimeout           time.Duration
	writeTimeout           time.Duration
	outputMode             string
	configmapNamespace     string
	configmapName          string
	observerPodName        string
	kubeconfig             string
}

// NewCommand wires the cobra command. ctx is owned by main() so signal
// handling lives there.
func NewCommand(ctx context.Context) *cobra.Command {
	o := &commandOptions{
		kmsSocket:              "/var/run/kmsplugin/kms.sock",
		probeInterval:          60 * time.Second,
		probeIntervalUnhealthy: 10 * time.Second,
		probeTimeout:           3 * time.Second,
		writeTimeout:           5 * time.Second,
		outputMode:             outputModeConfigMap,
	}
	cmd := &cobra.Command{
		Use:   "kms-health-monitor",
		Short: "Observes a co-located KMSv2 plugin and publishes a health status.",
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
	fs.StringVar(
		&o.kmsSocket,
		"kms-socket",
		o.kmsSocket,
		"filesystem path to the KMSv2 plugin UDS",
	)
	fs.DurationVar(
		&o.probeInterval,
		"probe-interval",
		o.probeInterval,
		"probe cadence while the plugin is healthy",
	)
	fs.DurationVar(
		&o.probeIntervalUnhealthy,
		"probe-interval-unhealthy",
		o.probeIntervalUnhealthy,
		"probe cadence after an unhealthy result until recovery",
	)
	fs.DurationVar(
		&o.probeTimeout,
		"probe-timeout",
		o.probeTimeout,
		"deadline for each Status RPC",
	)
	fs.DurationVar(
		&o.writeTimeout,
		"write-timeout",
		o.writeTimeout,
		"deadline for each status write (e.g. ConfigMap Update); should fit inside --probe-interval-unhealthy to preserve cadence under apiserver slowness",
	)
	fs.StringVar(
		&o.outputMode,
		"output-mode",
		o.outputMode,
		"status sink: configmap (condition is reserved for the OpenShift track)",
	)
	fs.StringVar(
		&o.configmapNamespace,
		"configmap-namespace",
		"",
		"namespace of the status ConfigMap (required when output-mode=configmap; "+
			"caller must have RBAC to patch ConfigMaps in this namespace)",
	)
	fs.StringVar(
		&o.configmapName,
		"configmap-name",
		"",
		"name of the status ConfigMap; defaults to \"kms-health-${POD_NAME}\". "+
			"MUST be unique per monitor instance: concurrent writers on one CM "+
			"produce last-writer-wins flap on every key",
	)
	fs.StringVar(
		&o.observerPodName,
		"observer-pod-name",
		os.Getenv("POD_NAME"),
		"pod name recorded in the status; defaults to $POD_NAME",
	)
	fs.StringVar(
		&o.kubeconfig,
		"kubeconfig",
		"",
		"path to a kubeconfig; empty uses in-cluster config",
	)
}

func (o *commandOptions) validate() error {
	if o.kmsSocket == "" {
		return fmt.Errorf("--kms-socket is required")
	}
	if o.probeInterval <= 0 {
		return fmt.Errorf("--probe-interval must be positive")
	}
	if o.probeIntervalUnhealthy <= 0 {
		return fmt.Errorf("--probe-interval-unhealthy must be positive")
	}
	if o.probeTimeout <= 0 {
		return fmt.Errorf("--probe-timeout must be positive")
	}
	if o.writeTimeout <= 0 {
		return fmt.Errorf("--write-timeout must be positive")
	}
	// $POD_NAME defaulting happens at flag-registration time in addFlags;
	// by here observerPodName is the flag, env, or genuinely empty.
	if o.observerPodName == "" {
		return fmt.Errorf(
			"--observer-pod-name is required (or set $POD_NAME)",
		)
	}
	switch o.outputMode {
	case outputModeConfigMap:
		if o.configmapNamespace == "" {
			return fmt.Errorf(
				"--configmap-namespace is required when --output-mode=%s",
				outputModeConfigMap,
			)
		}
		if o.configmapName == "" {
			// Wrap pod identity rather than using it bare. Advertises
			// ownership and avoids colliding with a same-namespaced CM
			// that some other component happens to name after the pod.
			o.configmapName = "kms-health-" + o.observerPodName
		}
	case outputModeCondition:
		return fmt.Errorf(
			"--output-mode=%s is reserved for the OpenShift track and not implemented",
			outputModeCondition,
		)
	default:
		return fmt.Errorf(
			"--output-mode must be %q or %q (got %q)",
			outputModeConfigMap,
			outputModeCondition,
			o.outputMode,
		)
	}
	return nil
}

func (o *commandOptions) run(ctx context.Context) error {
	cfg, err := buildRESTConfig(o.kubeconfig)
	if err != nil {
		return fmt.Errorf("build rest config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("build kubernetes client: %w", err)
	}

	writer := NewConfigMapWriter(client, o.configmapNamespace, o.configmapName)

	// WaitForReady(true) is set inside the kmsv2 client, so Dial returns
	// immediately even if the plugin isn't listening yet.
	endpoint := "unix://" + o.kmsSocket
	service, err := k8senvelopekmsv2.NewGRPCService(
		ctx,
		endpoint,
		providerName,
		o.probeTimeout,
	)
	if err != nil {
		return fmt.Errorf("dial KMS plugin at %q: %w", endpoint, err)
	}
	probe := NewProbe(service, 0)

	monitor := NewMonitor(
		probe,
		writer,
		o.observerPodName,
		o.probeInterval,
		o.probeIntervalUnhealthy,
		o.writeTimeout,
	)

	klog.InfoS("kms-health-monitor starting",
		"socket", o.kmsSocket,
		"configmap", o.configmapNamespace+"/"+o.configmapName,
		"observerPod", o.observerPodName,
		"healthyInterval", o.probeInterval,
		"unhealthyInterval", o.probeIntervalUnhealthy,
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
