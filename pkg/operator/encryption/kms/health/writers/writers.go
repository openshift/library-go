// Package writers provides the per-operator EncryptionStatusWriter
// implementations for the KMS health reporter.
//
// The health package builds the shared leaf (KMSEncryptionStatus) and ships the
// reporter command; each apiserver operator nests that leaf into a different
// status CR. These constructors carry that per-operator placement so an operator
// wires one function into health.NewCommand instead of hand-rolling the apply.
package writers

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
)

// NewAuthenticationWriter writes into Authentication/cluster at
// .status.oauthAPIServer.encryptionStatus. The auth operator manages the
// oauth-apiserver. There is an extra hop the other two operators don't have.
func NewAuthenticationWriter(restConfig *rest.Config, _ string) (health.EncryptionStatusWriter, error) {
	client, err := operatorclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
		_, err := client.OperatorV1().Authentications().ApplyStatus(
			ctx,
			applyoperatorv1.Authentication("cluster").WithStatus(
				applyoperatorv1.AuthenticationStatus().WithOAuthAPIServer(
					applyoperatorv1.OAuthAPIServerStatus().WithEncryptionStatus(status),
				),
			),

			// A single reporter writes this status, so a constant fieldManager
			// is enough and always fits the apiserver's length limit.
			metav1.ApplyOptions{FieldManager: health.Subcommand, Force: true},
		)
		return err
	}, nil
}

// NewKubeAPIServerWriter writes into KubeAPIServer/cluster at
// .status.encryptionStatus.
func NewKubeAPIServerWriter(restConfig *rest.Config, nodeName string) (health.EncryptionStatusWriter, error) {
	client, err := operatorclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}
	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	// One reporter runs per control-plane node and each applies its own row, so
	// the fieldManager must be per-node. The node UID is a fixed-length,
	// instance-stable identity that fits the fieldManager length limit, unlike
	// the node name (a DNS subdomain up to 253 chars).
	//
	// Lazy evaluation on first call as constructor isn't concerned with any context.
	var fieldManager string
	return func(ctx context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
		if fieldManager == "" {
			node, err := kubeClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("get node %q: %w", nodeName, err)
			}
			fieldManager = fmt.Sprintf("%s-%s", health.Subcommand, node.UID)
		}

		_, err := client.OperatorV1().KubeAPIServers().ApplyStatus(
			ctx,
			applyoperatorv1.KubeAPIServer("cluster").WithStatus(
				applyoperatorv1.KubeAPIServerStatus().WithEncryptionStatus(status),
			),
			metav1.ApplyOptions{FieldManager: fieldManager, Force: true},
		)
		return err
	}, nil
}

// NewOpenShiftAPIServerWriter writes into OpenShiftAPIServer/cluster at
// .status.encryptionStatus.
func NewOpenShiftAPIServerWriter(restConfig *rest.Config, _ string) (health.EncryptionStatusWriter, error) {
	client, err := operatorclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
		_, err := client.OperatorV1().OpenShiftAPIServers().ApplyStatus(
			ctx,
			applyoperatorv1.OpenShiftAPIServer("cluster").WithStatus(
				applyoperatorv1.OpenShiftAPIServerStatus().WithEncryptionStatus(status),
			),

			// A single reporter writes this status, so a constant fieldManager
			// is enough and always fits the apiserver's length limit.
			metav1.ApplyOptions{FieldManager: health.Subcommand, Force: true},
		)
		return err
	}, nil
}
