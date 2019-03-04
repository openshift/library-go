package installerpod

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openshift/library-go/pkg/config/client"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/staticpod/resourcecopy"
)

type CertCopyOptions struct {
	// TODO replace with genericclioptions
	KubeConfig string
	KubeClient kubernetes.Interface

	Revision  string
	Namespace string

	SecretNamePrefixes            []string
	OptionalSecretNamePrefixes    []string
	ConfigMapNamePrefixes         []string
	OptionalConfigMapNamePrefixes []string

	NameFn func(string) string

	DestinationDir string

	Timeout time.Duration
}

func NewCertCopyOptions() *CertCopyOptions {
	return &CertCopyOptions{}
}

func NewCertCopier() *cobra.Command {
	o := NewCertCopyOptions()

	cmd := &cobra.Command{
		Use:   "cert-copier",
		Short: "Copy secrets and configmaps",
		Run: func(cmd *cobra.Command, args []string) {
			glog.V(1).Info(cmd.Flags())
			glog.V(1).Info(spew.Sdump(o))

			if err := o.Complete(); err != nil {
				glog.Fatal(err)
			}
			if err := o.Validate(); err != nil {
				glog.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.TODO(), o.Timeout)
			defer cancel()
			if err := o.Run(ctx); err != nil {
				glog.Fatal(err)
			}
		},
	}

	o.AddFlags(cmd.Flags())

	return cmd
}

func (o *CertCopyOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.KubeConfig, "kubeconfig", o.KubeConfig, "kubeconfig file or empty")
	fs.StringVar(&o.Revision, "revision", o.Revision, "identifier for this particular installation instance.  For example, a counter or a hash")
	fs.StringVar(&o.Namespace, "namespace", o.Namespace, "namespace to retrieve all resources from and create the static pod in")
	fs.StringSliceVar(&o.SecretNamePrefixes, "secrets", o.SecretNamePrefixes, "list of secret names to be included")
	fs.StringSliceVar(&o.ConfigMapNamePrefixes, "configmaps", o.ConfigMapNamePrefixes, "list of configmaps to be included")
	fs.StringSliceVar(&o.OptionalSecretNamePrefixes, "optional-secrets", o.OptionalSecretNamePrefixes, "list of optional secret names to be included")
	fs.StringSliceVar(&o.OptionalConfigMapNamePrefixes, "optional-configmaps", o.OptionalConfigMapNamePrefixes, "list of optional configmaps to be included")
	fs.StringVar(&o.DestinationDir, "destination-dir", o.DestinationDir, "directory for all files")
	fs.DurationVar(&o.Timeout, "timeout-duration", 120*time.Second, "maximum time in seconds to wait for the copying to complete (default: 2m)")
}

func (o *CertCopyOptions) Complete() error {
	clientConfig, err := client.GetKubeConfigOrInClusterConfig(o.KubeConfig, nil)
	if err != nil {
		return err
	}

	// Use protobuf to fetch configmaps and secrets and create pods.
	protoConfig := rest.CopyConfig(clientConfig)
	protoConfig.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	protoConfig.ContentType = "application/vnd.kubernetes.protobuf"

	o.KubeClient, err = kubernetes.NewForConfig(protoConfig)
	if err != nil {
		return err
	}

	o.NameFn = func(prefix string) string {
		return nameFor(prefix, o.Revision)
	}

	return nil
}

func (o *CertCopyOptions) Validate() error {
	if len(o.Revision) == 0 {
		return fmt.Errorf("--revision is required")
	}
	if len(o.Namespace) == 0 {
		return fmt.Errorf("--namespace is required")
	}
	if len(o.ConfigMapNamePrefixes) == 0 {
		return fmt.Errorf("--configmaps is required")
	}
	if o.Timeout == 0 {
		return fmt.Errorf("--timeout-duration cannot be 0")
	}

	if o.KubeClient == nil {
		return fmt.Errorf("missing client")
	}

	return nil
}

func (o *CertCopyOptions) copyContent(ctx context.Context) error {
	secretPrefixes := sets.NewString(o.SecretNamePrefixes...)
	optionalSecretPrefixes := sets.NewString(o.OptionalSecretNamePrefixes...)
	configPrefixes := sets.NewString(o.ConfigMapNamePrefixes...)
	optionalConfigPrefixes := sets.NewString(o.OptionalConfigMapNamePrefixes...)

	secretSources := []resourcecopy.Source{}
	for _, secretPrefix := range append(secretPrefixes.List(), optionalSecretPrefixes.List()...) {
		if optionalSecretPrefixes.Has(secretPrefix) {
			secretSources = append(secretSources, resourcecopy.NewOptionalSourceWithMutation(o.Namespace, secretPrefix, o.NameFn))
			continue
		}
		secretSources = append(secretSources, resourcecopy.NewSourceWithMutation(o.Namespace, secretPrefix, o.NameFn))
	}

	err := resourcecopy.CopySecrets(ctx, o.KubeClient.CoreV1(), secretSources, func(secret *v1.Secret) error {
		contentDir := path.Join(o.DestinationDir, "secrets", prefixFor(secret.Name, o.Revision))
		glog.Infof("Creating directory %q ...", contentDir)
		if err := os.MkdirAll(contentDir, 0755); err != nil {
			return err
		}
		for filename, content := range secret.Data {
			// TODO fix permissions
			glog.Infof("Writing secret manifest %q ...", path.Join(contentDir, filename))
			if err := ioutil.WriteFile(path.Join(contentDir, filename), content, 0644); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to copy secrets: %v", err)
	}

	configSources := []resourcecopy.Source{}
	for _, configPrefix := range append(configPrefixes.List(), optionalConfigPrefixes.List()...) {
		if optionalConfigPrefixes.Has(configPrefix) {
			configSources = append(configSources, resourcecopy.NewOptionalSourceWithMutation(o.Namespace, configPrefix, o.NameFn))
			continue
		}
		configSources = append(configSources, resourcecopy.NewSourceWithMutation(o.Namespace, configPrefix, o.NameFn))
	}

	err = resourcecopy.CopyConfigMaps(ctx, o.KubeClient.CoreV1(), configSources, func(config *v1.ConfigMap) error {
		contentDir := path.Join(o.DestinationDir, "configmaps", prefixFor(config.Name, o.Revision))
		glog.Infof("Creating directory %q ...", contentDir)
		if err := os.MkdirAll(contentDir, 0755); err != nil {
			return err
		}
		for filename, content := range config.Data {
			// TODO fix permissions
			glog.Infof("Writing config map manifest %q ...", path.Join(contentDir, filename))
			if err := ioutil.WriteFile(path.Join(contentDir, filename), []byte(content), 0644); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to copy config maps: %v", err)
	}

	return nil
}

func (o *CertCopyOptions) Run(ctx context.Context) error {
	eventTarget, err := events.GetControllerReferenceForCurrentPodWithRetry(ctx, o.KubeClient, o.Namespace, nil)
	if err != nil {
		return err
	}

	recorder := events.NewRecorder(o.KubeClient.CoreV1().Events(o.Namespace), "cert-copier", eventTarget)
	if err := o.copyContent(ctx); err != nil {
		recorder.Warningf("StaticPodCertCopierFailed", "CertCopying revision %s: %v", o.Revision, err)
		return fmt.Errorf("failed to copy: %v", err)
	}

	recorder.Eventf("StaticPodCertCopierCompleted", "Successfully installed revision %s", o.Revision)
	return nil
}
