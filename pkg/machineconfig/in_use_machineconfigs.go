package machineconfig

import (
	"context"
	"fmt"

	mcfgclientset "github.com/openshift/client-go/machineconfiguration/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// GetInUseMachineConfigs filters in-use MachineConfig resources and returns set of their names.
func GetInUseMachineConfigs(ctx context.Context, clientConfig *rest.Config, poolFilter string) (sets.Set[string], error) {
	// Create a set to store in-use configs
	inuseConfigs := sets.New[string]()

	machineConfigClient, err := mcfgclientset.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	poolList, err := machineConfigClient.MachineconfigurationV1().MachineConfigPools().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting MachineConfigPools failed: %w", err)
	}

	for _, pool := range poolList.Items {
		// Check if the pool matches the specified pool name (if provided)
		if poolFilter == "" || poolFilter == pool.Name {
			// Get the rendered config name from the status section
			inuseConfigs.Insert(pool.Status.Configuration.Name)
			inuseConfigs.Insert(pool.Spec.Configuration.Name)
		}
	}

	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}
	nodeList, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, node := range nodeList.Items {
		current, ok := node.Annotations["machineconfiguration.openshift.io/currentConfig"]
		if ok {
			inuseConfigs.Insert(current)
		}
		desired, ok := node.Annotations["machineconfiguration.openshift.io/desiredConfig"]
		if ok {
			inuseConfigs.Insert(desired)
		}
	}

	return inuseConfigs, nil
}
