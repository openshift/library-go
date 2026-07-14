package health

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/pflag"

	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/clientcmd"
)

// options' flag-bound fields are exported so the struct can be logged as a
// whole via klog.InfoS, which JSON-marshals its values.
type options struct {
	KMSSockets   []string
	Interval     time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	NodeName     string
	Kubeconfig   string

	newClient NewKMSEncryptionStatusClientFunc
}

func (o *options) addFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&o.KMSSockets, "kms-sockets", nil, "KMS plugin endpoints in unix:// URI format (e.g. unix:///var/run/kmsplugin/kms-1.sock)")
	fs.DurationVar(&o.Interval, "interval", 30*time.Second, "cadence between probe+emit cycles")
	fs.DurationVar(&o.ReadTimeout, "read-timeout", 5*time.Second, "deadline for each Status RPC")
	fs.DurationVar(&o.WriteTimeout, "write-timeout", 10*time.Second, "deadline for each condition update")
	fs.StringVar(&o.NodeName, "node-name", "", "identifier for this reporter: must be unique among reporters writing to the same operator CR")
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
	if fieldManager := fmt.Sprintf("%s-%s", Subcommand, o.NodeName); len(fieldManager) > metav1validation.FieldManagerMaxLength {
		return fmt.Errorf("--node-name too long: reporter identity %q is %d chars, exceeds the %d-char fieldManager limit", fieldManager, len(fieldManager), metav1validation.FieldManagerMaxLength)
	}

	return nil
}

func (o *options) Config(ctx context.Context) (*Config, error) {
	// Empty kubeconfig falls back to the in-cluster config (service account
	// token + KUBERNETES_SERVICE_HOST), which is the deployed path.
	restCfg, err := clientcmd.BuildConfigFromFlags("", o.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("build rest config: %w", err)
	}

	// fieldManager is this reporter's SSA ownership identity: apply tracks
	// ownership per manager. Reporters sharing one would fight over the same
	// CR status.
	// kube-apiserver runs one reporter per node: node-name must be unique!
	// single-reporter operators, like oauth- / openshift-apiserver, can pass
	// any constant value.
	fieldManager := fmt.Sprintf("%s-%s", Subcommand, o.NodeName)
	statusClient, err := o.newClient(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build encryption status client: %w", err)
	}

	plugins, err := buildPlugins(ctx, o.KMSSockets, o.ReadTimeout)
	if err != nil {
		return nil, err
	}

	return &Config{
		statusClient: statusClient,
		prober:       newProber(o.NodeName, plugins),
		fieldManager: fieldManager,
		interval:     o.Interval,
		writeTimeout: o.WriteTimeout,
	}, nil
}
