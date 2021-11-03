package clusterstatus

import (
	"context"

	configv1 "github.com/openshift/api/config/v1"
	openshiftcorev1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

const infraResourceName = "cluster"

func GetClusterInfraStatus(ctx context.Context, restClient *rest.Config) (*configv1.InfrastructureStatus, error) {
	client, err := openshiftcorev1.NewForConfig(restClient)
	if err != nil {
		return nil, err
	}
	infra, err := client.Infrastructures().Get(ctx, infraResourceName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return &infra.Status, nil
}

func GetClusterInfraStatusOrDie(ctx context.Context, restClient *rest.Config) *configv1.InfrastructureStatus {
	infra, err := GetClusterInfraStatus(ctx, restClient)
	if err != nil {
		panic(err)
	}
	return infra
}
