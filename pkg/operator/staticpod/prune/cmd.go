package prune

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/openshift/library-go/pkg/config/client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
)

type PruneOptions struct {
	KubeConfig string
	KubeClient kubernetes.Interface

	MaxEligibleRevisionID int
	ProtectedRevisionIDs  []int

	ResourceDir     string
	StaticPodName   string
	TargetNamespace string
}

func NewPruneOptions() *PruneOptions {
	return &PruneOptions{}
}

func NewPrune() *cobra.Command {
	o := NewPruneOptions()

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Prune static pod installer revisions",
		Run: func(cmd *cobra.Command, args []string) {
			glog.V(1).Info(cmd.Flags())
			glog.V(1).Info(spew.Sdump(o))
			if err := o.Complete(); err != nil {
				glog.Fatal(err)
			}
			if err := o.Validate(); err != nil {
				glog.Fatal(err)
			}
			if err := o.Run(); err != nil {
				glog.Fatal(err)
			}
		},
	}

	o.AddFlags(cmd.Flags())

	return cmd
}

func (o *PruneOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.KubeConfig, "kubeconfig", o.KubeConfig, "kubeconfig file or empty")
	fs.IntVar(&o.MaxEligibleRevisionID, "max-eligible-id", o.MaxEligibleRevisionID, "highest revision ID to be eligible for pruning")
	fs.IntSliceVar(&o.ProtectedRevisionIDs, "protected-ids", o.ProtectedRevisionIDs, "list of revision IDs to preserve (not delete)")
	fs.StringVar(&o.ResourceDir, "resource-dir", o.ResourceDir, "directory for all files supporting the static pod manifest")
	fs.StringVar(&o.StaticPodName, "static-pod-name", o.StaticPodName, "name of the static pod")
	fs.StringVar(&o.TargetNamespace, "namespace", o.TargetNamespace, "namespace of the static pod")
}

func (o *PruneOptions) Validate() error {
	if len(o.ResourceDir) == 0 {
		return fmt.Errorf("--resource-dir is required")
	}
	if o.MaxEligibleRevisionID == 0 {
		return fmt.Errorf("--max-eligible-id is required")
	}
	if len(o.StaticPodName) == 0 {
		return fmt.Errorf("--static-pod-name is required")
	}

	return nil
}

func (o *PruneOptions) Complete() error {
	clientConfig, err := client.GetKubeConfigOrInClusterConfig(o.KubeConfig, nil)
	if err != nil {
		return err
	}
	o.KubeClient, err = kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return err
	}
	return nil
}

func (o *PruneOptions) pruneLocalFiles(protectedIDs sets.Int) error {
	files, err := ioutil.ReadDir(o.ResourceDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		// If the file is not a resource directory...
		if !file.IsDir() {
			continue
		}
		// And doesn't match our static pod prefix...
		if !strings.HasPrefix(file.Name(), o.StaticPodName) {
			continue
		}

		// Split file name to get just the integer revision ID
		fileSplit := strings.Split(file.Name(), o.StaticPodName+"-")
		revisionID, err := strconv.Atoi(fileSplit[len(fileSplit)-1])
		if err != nil {
			return err
		}

		// And is not protected...
		if protected := protectedIDs.Has(revisionID); protected {
			continue
		}
		// And is less than or equal to the maxEligibleRevisionID
		if revisionID > o.MaxEligibleRevisionID {
			continue
		}

		err = os.RemoveAll(path.Join(o.ResourceDir, file.Name()))
		if err != nil {
			return err
		}
	}
}

func (o *PruneOptions) pruneAPIResources(protectedIDs sets.Int) error {
	labelSelector := labels.SelectorFromSet(labels.Set{"role": "revision-status"}).String()
	statusConfigMaps, err := o.KubeClient.CoreV1().ConfigMaps(o.TargetNamespace).List(metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return err
	}
	for _, cm := range statusConfigMaps.Items {
		revision, err := strconv.Atoi(cm.Data["revision"])
		if err != nil {
			return err
		}

		if protected := protectedIDs.Has(revision); protected {
			continue
		}
		if revision > o.MaxEligibleRevisionID {
			continue
		}
		err = o.KubeClient.CoreV1().ConfigMaps(o.TargetNamespace).Delete(cm.Name, &metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *PruneOptions) Run() error {
	protectedIDs := sets.NewInt(o.ProtectedRevisionIDs...)
	if err := o.pruneLocalFiles(protectedIDs); err != nil {
		return err
	}

	return o.pruneAPIResources(protectedIDs)
}
