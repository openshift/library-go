package events

import (
	"fmt"
	"os"
	"time"

	"github.com/golang/glog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// Recorder is a simple event recording interface.
type Recorder interface {
	Event(reason, message string)
	Eventf(reason, messageFmt string, args ...interface{})
	Warning(reason, message string)
	Warningf(reason, messageFmt string, args ...interface{})
}

// podNameEnv is a name of environment variable inside container that specifies the name of the current replica set.
// This replica set name is then used as a source/involved object for operator events.
const podNameEnv = "POD_NAME"

// podNameEnvFunc allows to override the way we get the environment variable value (for unit tests).
var podNameEnvFunc = func() string {
	return os.Getenv(podNameEnv)
}

// GetControllerReferenceForCurrentPod provides an object reference to a controller managing the pod/container where this process runs.
// The pod name must be provided via the POD_NAME name.
func GetControllerReferenceForCurrentPod(client corev1client.PodInterface) (*corev1.ObjectReference, error) {
	podName := podNameEnvFunc()
	if len(podName) == 0 {
		return guessControllerReferenceForNamespace(client)
	}
	pod, err := client.Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	ownerRef := metav1.GetControllerOf(pod)
	return &corev1.ObjectReference{
		Kind:       ownerRef.Kind,
		Namespace:  pod.Namespace,
		Name:       ownerRef.Name,
		UID:        ownerRef.UID,
		APIVersion: ownerRef.APIVersion,
	}, nil
}

// guessControllerReferenceForNamespace tries to guess what resource to reference.
func guessControllerReferenceForNamespace(client corev1client.PodInterface) (*corev1.ObjectReference, error) {
	pods, err := client.List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("unable to setup event recorder as %q env variable is not set and there are no pods", podNameEnv)
	}

	pod := &pods.Items[0]
	ownerRef := metav1.GetControllerOf(pod)
	return &corev1.ObjectReference{
		Kind:       ownerRef.Kind,
		Namespace:  pod.Namespace,
		Name:       ownerRef.Name,
		UID:        ownerRef.UID,
		APIVersion: ownerRef.APIVersion,
	}, nil
}

// NewRecorder returns new event recorder.
func NewRecorder(client corev1client.EventInterface, sourceComponentName string, involvedObjectRef *corev1.ObjectReference) Recorder {
	return &recorder{
		eventClient:       client,
		involvedObjectRef: involvedObjectRef,
		sourceComponent:   sourceComponentName,
	}
}

// recorder is an implementation of Recorder interface.
type recorder struct {
	eventClient       corev1client.EventInterface
	involvedObjectRef *corev1.ObjectReference
	sourceComponent   string
}

// Event emits the normal type event and allow formatting of message.
func (r *recorder) Eventf(reason, messageFmt string, args ...interface{}) {
	r.Event(reason, fmt.Sprintf(messageFmt, args...))
}

// Warning emits the warning type event and allow formatting of message.
func (r *recorder) Warningf(reason, messageFmt string, args ...interface{}) {
	r.Warning(reason, fmt.Sprintf(messageFmt, args...))
}

// Event emits the normal type event.
func (r *recorder) Event(reason, message string) {
	event := makeEvent(r.involvedObjectRef, r.sourceComponent, corev1.EventTypeNormal, reason, message)
	if _, err := r.eventClient.Create(event); err != nil {
		glog.Warningf("Error creating event %+v: %v", event, err)
	}
}

// Warning emits the warning type event.
func (r *recorder) Warning(reason, message string) {
	event := makeEvent(r.involvedObjectRef, r.sourceComponent, corev1.EventTypeWarning, reason, message)
	if _, err := r.eventClient.Create(event); err != nil {
		glog.Warningf("Error creating event %+v: %v", event, err)
	}
}

func makeEvent(involvedObjRef *corev1.ObjectReference, sourceComponent string, eventType, reason, message string) *corev1.Event {
	currentTime := metav1.Time{Time: time.Now()}
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%v.%x", involvedObjRef.Name, currentTime.UnixNano()),
			Namespace: involvedObjRef.Namespace,
		},
		InvolvedObject: *involvedObjRef,
		Reason:         reason,
		Message:        message,
		Type:           eventType,
		Count:          1,
		FirstTimestamp: currentTime,
		LastTimestamp:  currentTime,
	}
	event.Source.Component = sourceComponent
	return event
}
