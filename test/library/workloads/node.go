package workloads

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

func CordonNode(ctx context.Context, client kubernetes.Interface, nodeName string) error {
	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	if node.Spec.Unschedulable {
		return nil
	}

	return patchNode(ctx, client, node, true)
}

func UncordonNode(ctx context.Context, client kubernetes.Interface, nodeName string) error {
	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	if !node.Spec.Unschedulable {
		return nil
	}

	return patchNode(ctx, client, node, false)
}

func patchNode(ctx context.Context, client kubernetes.Interface, node *corev1.Node, unschedulable bool) error {
	patch := []byte(fmt.Sprintf(`{"spec":{"unschedulable":%t}}`, unschedulable))
	_, err := client.CoreV1().Nodes().Patch(ctx, node.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to patch node %s: %w", node.Name, err)
	}
	return nil
}
