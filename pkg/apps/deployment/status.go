package deployment

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelistersv1 "k8s.io/client-go/listers/core/v1"
)

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
			if c.Ready {
				continue
			}

			if c.State.Terminated != nil && c.State.Terminated.ExitCode != 0 {
				failedCount++
				continue
			}

			// we tolerate 1 restart for cert reloading
			if c.RestartCount > 1 {
				restartCount++
			}

			if c.State.Waiting != nil {
				waitingCount++
				continue
			}

			if c.RestartCount <= 1 {
				notReadyCount++
			}
		}

		if failedCount > 0 {
			containerStates = append(containerStates, fmt.Sprintf("%s crashed in %s pod", containerPlural(failedCount, false), deploymentPods[i].Name))
		}

		if waitingCount > 0 {
			containerStates = append(containerStates, fmt.Sprintf("%s waiting in %s", containerPlural(waitingCount, restartCount > 0), podPhase(deploymentPods[i])))
		}

		if restartCount > 0 && waitingCount == 0 {
			containerStates = append(containerStates, fmt.Sprintf("%s crashlooping in %s", containerPlural(restartCount, false), podPhase(deploymentPods[i])))
		}

		if notReadyCount > 0 {
			containerStates = append(containerStates, fmt.Sprintf("%s not ready in %s", containerPlural(notReadyCount, false), podPhase(deploymentPods[i])))
		}
	}

	if len(deploymentPods) == 0 {
		containerStates = append(containerStates, fmt.Sprintf("no pods found with labels %q", labels.SelectorFromSet(deployment.Spec.Template.Labels).String()))
	}
	return containerStates, nil
}

func containerPlural(c int, crashloop bool) string {
	crash := ""
	if crashloop {
		crash = "crashlooping "
	}
	if c == 1 {
		return fmt.Sprintf("%scontainer is", crash)
	}
	return fmt.Sprintf("%d %scontainers are", c, crash)
}

func podPhase(pod *corev1.Pod) string {
	switch pod.Status.Phase {
	case corev1.PodSucceeded:
		return fmt.Sprintf("terminated %s pod", pod.Name)
	case corev1.PodPending:
		return fmt.Sprintf("pending %s pod", pod.Name)
	default:
		return fmt.Sprintf("%s pod", pod.Name)
	}
}
