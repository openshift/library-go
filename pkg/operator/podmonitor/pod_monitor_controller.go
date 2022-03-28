package podmonitor

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	coreapiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type LogMatchConfig struct {
	// Pattern is a regular expression of a pattern to match in container termination message OR container log
	Pattern string

	// If a pattern is matched, add this message to the resulting event or operator condition
	Message string
	// If a pattern is matched, use this reason for an event or operator condition
	Reason string
}

type PodContainerConfig struct {
	// Pod container name to match
	Name string

	// LogMatches is a list of patterns to scan the failed container logs and termination message for
	LogMatches []LogMatchConfig

	// MinimumRestartCount is the minimum number of restarts to tolerate for the container
	MinimumRestartCount int32
}

type PodMonitorConfig struct {
	// Name of the pod to match in a namespace
	Name string

	// List of pod containers to check
	ContainerConfig []PodContainerConfig
}

type controller struct {
	namespace      string
	podConfigs     []PodMonitorConfig
	podLister      corev1listers.PodLister
	podLogs        clientcorev1.PodInterface
	operatorClient v1helpers.OperatorClient
}

// NewPodMonitorController creates a controller that aim to monitor crashlooping containers inside pods.
// Caller can setup monitors that watch the pods in target namespaces and if the restart count threshold is reached, a set of log matchers are ran on the crashed container logs and termination message
// to determine how the crash will be reported. This allows to setup fine-tunes monitoring for container crashes or general purpose monitor for crashing containers.
func NewPodMonitorController(targetNamespace string, operatorClient v1helpers.OperatorClient, informers v1helpers.KubeInformersForNamespaces, podLogsClient clientcorev1.PodInterface, recorder events.Recorder, podMonitors []PodMonitorConfig) factory.Controller {
	c := &controller{
		namespace:      targetNamespace,
		podConfigs:     podMonitors,
		podLister:      informers.InformersFor(targetNamespace).Core().V1().Pods().Lister(),
		podLogs:        podLogsClient,
		operatorClient: operatorClient,
	}
	return factory.New().
		ResyncEvery(10*time.Minute).
		WithSync(c.sync).
		WithInformers(
			operatorClient.Informer(),
			informers.InformersFor(targetNamespace).Core().V1().Pods().Informer(),
		).ToController("PodCheckerController", recorder)
}

// terminatedContainer stores metadata for a container that were detected and flagged by this controller as crashing.
type terminatedContainer struct {
	podName       string
	containerName string
	exitCode      int32
	restartCount  int32
	lastRestart   time.Time

	message string
	reason  string
}

func (t terminatedContainer) String() string {
	return fmt.Sprintf("container %s in %s pod restarted %d times, last restart at %s with exit code %d: %s", t.containerName, t.podName, t.restartCount, t.lastRestart, t.exitCode, t.message)
}

func (c *controller) sync(ctx context.Context, syncContext factory.SyncContext) error {
	// this lists all pods from specified target namespace.
	pods, err := c.podLister.List(labels.Everything())
	if err != nil {
		return nil
	}
	terminatedContainers := []terminatedContainer{}

	for i := range pods {
		// check if we have pod monitor configured for this pod
		pc := c.getPodMonitor(pods[i].Name)
		if pc == nil {
			continue
		}

		for _, containerStatus := range pods[i].Status.ContainerStatuses {
			// check if we monitor this container in pod
			cc := pc.getContainerConfigFor(containerStatus.Name)
			if cc == nil {
				continue
			}

			// only continue if the minimum restart count threshold is reached
			if containerStatus.RestartCount < cc.MinimumRestartCount {
				continue
			}

			// only continue on containers that were terminated
			// TODO: expand this to detect "stucked" containers (in waiting for long time)
			lastTerminated := containerStatus.LastTerminationState.Terminated
			if lastTerminated == nil || lastTerminated.ExitCode == 0 {
				continue
			}

			// at this point we have container that crashed and should be reported
			candidateContainer := &terminatedContainer{
				podName:       pods[i].Name,
				containerName: containerStatus.Name,
				exitCode:      lastTerminated.ExitCode,
				restartCount:  containerStatus.RestartCount,
				lastRestart:   lastTerminated.FinishedAt.Time,
			}

			// there are no log matches configured, just report crashing container
			if len(cc.LogMatches) == 0 {
				candidateContainer.reason = "MinimumRestartCount"
				candidateContainer.message = fmt.Sprintf("minimum restart count %d of reached", cc.MinimumRestartCount)
				terminatedContainers = append(terminatedContainers, *candidateContainer)
				continue
			}

			for _, p := range cc.LogMatches {
				ptr := regexp.MustCompile(p.Pattern)

				// first try to scan the termination message and see if we can get a hit
				if ptr.MatchString(lastTerminated.Message) {
					matchedCandidate := *candidateContainer
					matchedCandidate.message = p.Message
					matchedCandidate.reason = p.Reason
					terminatedContainers = append(terminatedContainers, matchedCandidate)
					continue
				}

				// if not, check the container logs and scan that for configured patterns.
				// if found, this will make the reported error more accurate
				tailLines := int64(500)
				request := c.podLogs.GetLogs(pods[i].Name, &coreapiv1.PodLogOptions{
					Container:                    containerStatus.Name,
					Previous:                     true,
					InsecureSkipTLSVerifyBackend: true,
					TailLines:                    &tailLines,
				})
				resultBytes, err := request.Do(ctx).Raw()
				if err != nil {
					klog.Errorf("unable to fetch logs for pod %q container %q: %v", pods[i].Name, containerStatus.Name, err)
					continue
				}
				if ptr.Match(resultBytes) {
					matchedCandidate := *candidateContainer
					matchedCandidate.message = p.Message
					matchedCandidate.reason = p.Reason
					terminatedContainers = append(terminatedContainers, matchedCandidate)
				}
			}
		}
	}

	// TODO: replace this with operator conditions or something that won't create too much churn
	for _, t := range terminatedContainers {
		syncContext.Recorder().Warningf(fmt.Sprintf("PodCheck%s", t.reason), t.String())
	}

	return nil
}

func (c *controller) getPodMonitor(name string) *PodMonitorConfig {
	for i := range c.podConfigs {
		if strings.Contains(c.podConfigs[i].Name, name) {
			return &c.podConfigs[i]
		}
	}
	return nil
}

func (p *PodMonitorConfig) getContainerConfigFor(name string) *PodContainerConfig {
	for i := range p.ContainerConfig {
		if strings.Contains(p.ContainerConfig[i].Name, name) {
			return &p.ContainerConfig[i]
		}
	}
	return nil
}
