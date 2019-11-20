package library

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// ForwardPodPortAndExecute forwards a local port to a pod port and executes the supplied func
func ForwardPodPortAndExecute(t *testing.T, kubeConfig *rest.Config, pod *corev1.Pod, podPort int, consumer func(localPort int) error) error {
	// pod must be running
	if pod.Status.Phase != corev1.PodRunning {
		return fmt.Errorf("pod must be running")
	}

	//setup port forwarding
	transport, upgrader, err := spdy.RoundTripperFor(kubeConfig)
	if err != nil {
		return err
	}
	restClient, err := rest.RESTClientFor(SetRESTConfigDefaults(kubeConfig))
	require.NoError(t, err)
	request := restClient.Post().Resource("pods").Namespace(pod.Namespace).Name(pod.Name).SubResource("portforward")
	localPort, err := FreeLocalTCPPort()
	if err != nil {
		return err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, request.URL())
	ports := []string{fmt.Sprintf("%d:%d", localPort, podPort)}
	stop := make(chan struct{}, 1)
	ready := make(chan struct{}, 1)
	portForwarder, err := portforward.New(dialer, ports, stop, ready, bytes.NewBuffer(nil), ioutil.Discard)
	if err != nil {
		return err
	}

	// error from consumer function
	var ferr error

	// run consumer function
	go func() {
		// stop port forwarding when done
		if stop != nil {
			defer close(stop)
		}
		t.Log("Waiting for port forwarder to be ready...")
		<-ready
		t.Log("Port forwarder is ready.")
		t.Log("Executing function...")
		ferr = consumer(localPort)
	}()

	t.Log("Starting port forwarder...")
	err = portForwarder.ForwardPorts()
	if err != nil {
		return err
	}

	<-stop
	t.Log("Port forwarder has stopped.")
	return ferr
}

func SetRESTConfigDefaults(config *rest.Config) *rest.Config {
	if config.GroupVersion == nil {
		config.GroupVersion = &schema.GroupVersion{Group: "", Version: "v1"}
	}
	if config.NegotiatedSerializer == nil {
		config.NegotiatedSerializer = scheme.Codecs
	}
	if len(config.UserAgent) == 0 {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}
	config.APIPath = "/api"
	return config
}
