package health

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/spf13/pflag"

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

	newProvider NewEncryptionStatusProviderFunc
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

	return nil
}

// fieldManagerForNode returns the SSA field manager for a reporter on nodeName.
// Node names can exceed the fieldManager length limit, so the name is hashed to
// a fixed-size SHA-256 hex digest while the prober still reports the real name.
func fieldManagerForNode(nodeName string) string {
	sum := sha256.Sum256([]byte(nodeName))
	return fmt.Sprintf("%s-%x", Subcommand, sum)
}

func (o *options) Config(ctx context.Context) (*Config, error) {
	// Empty kubeconfig falls back to the in-cluster config (service account
	// token + KUBERNETES_SERVICE_HOST), which is the deployed path.
	restCfg, err := clientcmd.BuildConfigFromFlags("", o.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("build rest config: %w", err)
	}

	provider, err := o.newProvider(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build encryption status provider: %w", err)
	}

	plugins, err := buildPlugins(ctx, o.KMSSockets, o.ReadTimeout)
	if err != nil {
		return nil, err
	}

	// fieldManager is this reporter's SSA ownership identity: apply tracks
	// ownership per manager. Reporters sharing one would fight over the same
	// CR status.
	// kube-apiserver runs one reporter per node: node-name must be unique!
	// single-reporter operators, like oauth- / openshift-apiserver, can pass
	// any constant value.
	return &Config{
		provider:     provider,
		fieldManager: fieldManagerForNode(o.NodeName),
		prober:       newProber(o.NodeName, plugins),
		interval:     o.Interval,
		writeTimeout: o.WriteTimeout,
	}, nil
}
