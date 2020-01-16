package apiservercontrollerset

import (
	"k8s.io/apimachinery/pkg/labels"
	appsv1informers "k8s.io/client-go/informers/apps/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"

	encryptiondeployer "github.com/openshift/library-go/pkg/operator/encryption/deployer"
)

// DaemonSetNodeProvider returns the node list from nodes matching the node selector of a DaemonSet
type DaemonSetNodeProvider struct {
	targetDaemonSetName, targetDaemonSetNamespace string
	targetNamespaceDaemonSetInformer              appsv1informers.DaemonSetInformer
	nodeInformer                                  corev1informers.NodeInformer
}

var (
	_ encryptiondeployer.MasterNodeProvider = &DaemonSetNodeProvider{}
)

// NewDaemonSetNodeProvider creates a new DaemonSetNodeProvider
func NewDaemonSetNodeProvider(
	targetName, targetNamespace string,
	targetDSInformer appsv1informers.DaemonSetInformer,
	nodeInformer corev1informers.NodeInformer,
) *DaemonSetNodeProvider {
	return &DaemonSetNodeProvider{
		targetDaemonSetName:              targetName,
		targetDaemonSetNamespace:         targetNamespace,
		targetNamespaceDaemonSetInformer: targetDSInformer,
		nodeInformer:                     nodeInformer,
	}
}

func (p *DaemonSetNodeProvider) MasterNodeNames() ([]string, error) {
	ds, err := p.targetNamespaceDaemonSetInformer.Lister().DaemonSets(p.targetDaemonSetNamespace).Get(p.targetDaemonSetName)
	if err != nil {
		return nil, err
	}

	nodes, err := p.nodeInformer.Lister().List(labels.SelectorFromSet(ds.Spec.Template.Spec.NodeSelector))
	if err != nil {
		return nil, err
	}

	ret := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ret = append(ret, n.Name)
	}

	return ret, nil
}

func (p *DaemonSetNodeProvider) AddEventHandler(handler cache.ResourceEventHandler) []cache.InformerSynced {
	p.targetNamespaceDaemonSetInformer.Informer().AddEventHandler(handler)
	p.nodeInformer.Informer().AddEventHandler(handler)

	return []cache.InformerSynced{
		p.targetNamespaceDaemonSetInformer.Informer().HasSynced,
		p.nodeInformer.Informer().HasSynced,
	}
}
