package staticpodcontroller

import (
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"k8s.io/client-go/tools/cache"
)

type OperatorClient interface {
	Informer() cache.SharedIndexInformer
	Get() (*operatorv1alpha1.OperatorSpec, *StaticPodConfigStatus, string, error)
	UpdateStatus(string, *StaticPodConfigStatus) (*StaticPodConfigStatus, error)
}

// TODO move to openshift/api I think

type StaticPodConfigStatus struct {
	operatorv1alpha1.OperatorStatus `json:",inline"`

	// latestDeploymentID is the deploymentID of the most recent deployment
	LatestDeploymentID int32 `json:"latestDeploymentID"`

	TargetKubeletStates []KubeletState `json:"kubeletStates"`
}

type KubeletState struct {
	NodeName string `json:"nodeName"`

	// currentDeploymentID is the ID of the most recently successful deployment
	CurrentDeploymentID int32 `json:"currentDeploymentID"`
	// targetDeploymentID is the ID of the deployment we're trying to apply
	TargetDeploymentID int32 `json:"targetDeploymentID"`
	// lastFailedDeploymentID is the ID of the deployment we tried and failed to deploy.
	LastFailedDeploymentID int32 `json:"lastFailedDeploymentID"`

	// errors is a list of the errors during the deployment installation
	Errors []string `json:"errors"`
}
