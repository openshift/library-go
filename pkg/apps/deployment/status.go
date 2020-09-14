package deployment

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
)

func containerPlural(c int) string {
	if c == 1 {
		return fmt.Sprintf("%d container is", c)
	}
	return fmt.Sprintf("%d containers are", c)
}

func podPhase(pod *corev1.Pod) string {
	switch pod.Status.Phase {
	case corev1.PodSucceeded:
		return fmt.Sprintf("terminated pod %s", pod.Name)
	case corev1.PodFailed:
		return fmt.Sprintf("failed pod %s", pod.Name)
	case corev1.PodPending:
		return fmt.Sprintf("pending pod %s", pod.Name)
	default:
		return fmt.Sprintf("pod %s", pod.Name)
	}
}

// PodContainersStatus return detailed information about deployment pods and the containers status in human readable format.
// This can be used for cluster operator condition messages or logging.
func PodContainersStatus(deployment *appsv1.Deployment, podClient corelistersv1.PodLister) ([]string, error) {
	deploymentPods, err := podClient.Pods(deployment.Namespace).List(labels.SelectorFromSet(deployment.Spec.Template.Labels))
	if err != nil {
		return nil, err
	}
	containerStates := []string{}

	for i := range deploymentPods {
		waitingCount := 0
		failedCount := 0
		restartCount := 0
		notReadyCount := 0

		for _, c := range append(deploymentPods[i].Status.ContainerStatuses, deploymentPods[i].Status.InitContainerStatuses...) {
			if !c.Ready {
				notReadyCount++
			}
			// we tolerate 1 restart for cert reloading
			if c.RestartCount > 1 {
				restartCount++
			}
			if c.State.Terminated != nil && c.State.Terminated.ExitCode != 0 {
				failedCount++
			}
			if c.State.Waiting != nil {
				waitingCount++
			}
		}

		if waitingCount > 0 {
			containerStates = append(containerStates, fmt.Sprintf("%s waiting in %s", containerPlural(waitingCount), podPhase(deploymentPods[i])))
		}
		if failedCount > 0 {
			containerStates = append(containerStates, fmt.Sprintf("%s crashed in pod %s", containerPlural(failedCount), deploymentPods[i].Name))
		}
		if restartCount > 0 {
			containerStates = append(containerStates, fmt.Sprintf("%s crash-looping in %s", containerPlural(restartCount), podPhase(deploymentPods[i])))
		}
		if notReadyCount > 0 {
			containerStates = append(containerStates, fmt.Sprintf("%s not ready in %s", containerPlural(notReadyCount), podPhase(deploymentPods[i])))
		}
	}

	if len(deploymentPods) == 0 {
		containerStates = append(containerStates, fmt.Sprintf("no pods found with labels %q", labels.SelectorFromSet(deployment.Spec.Template.Labels).String()))
	}
	return containerStates, nil
}
