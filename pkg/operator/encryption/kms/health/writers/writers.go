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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
)

// NewAuthenticationWriter writes into Authentication/cluster at
// .status.oauthAPIServer.encryptionStatus. The auth operator manages the
// oauth-apiserver. There is an extra hop the other two operators don't have.
func NewAuthenticationWriter(restConfig *rest.Config, fieldManager string) (health.EncryptionStatusWriter, error) {
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

			metav1.ApplyOptions{FieldManager: fieldManager, Force: true},
		)
		return err
	}, nil
}

// NewKubeAPIServerWriter writes into KubeAPIServer/cluster at
// .status.encryptionStatus.
func NewKubeAPIServerWriter(restConfig *rest.Config, fieldManager string) (health.EncryptionStatusWriter, error) {
	client, err := operatorclient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
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
func NewOpenShiftAPIServerWriter(restConfig *rest.Config, fieldManager string) (health.EncryptionStatusWriter, error) {
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

			metav1.ApplyOptions{FieldManager: fieldManager, Force: true},
		)
		return err
	}, nil
}
