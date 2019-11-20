package library

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// GetMetricsForPod returns the metrics found at /metrics for a given pod.
func GetMetricsForPod(t *testing.T, kubeConfig *rest.Config, pod *v1.Pod, metricPort int) (map[string]string, error) {
	data := bytes.NewBuffer(nil)

	// function to get metrics at localhost:localPort/metrics
	getMetricsFunc := func(localPort int) error {
		// create config that uses the local port
		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{
				ClusterInfo: api.Cluster{
					InsecureSkipTLSVerify: true,
					Server:                fmt.Sprintf("https://localhost:%d", localPort),
				},
			},
		).ClientConfig()
		if err != nil {
			return err
		}
		config = SetRESTConfigDefaults(config)
		restClient, err := rest.RESTClientFor(config)
		if err != nil {
			return err
		}
		t.Log("Retrieving metrics...")
		stream, err := restClient.Get().RequestURI("/metrics").Stream()
		if err != nil {
			return err
		}
		defer stream.Close()
		_, err = io.Copy(data, stream)
		return err
	}

	// we need to port-forward to the pod metric endpoint so that we can get metrics from from outside the cluster
	err := ForwardPodPortAndExecute(t, kubeConfig, pod, metricPort, getMetricsFunc)
	if err != nil {
		return nil, err
	}

	// parse raw metrics output into a map
	metrics := map[string]string{}
	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		entry := strings.SplitN(line, " ", 2)
		metrics[entry[0]] = entry[1]
	}
	err = scanner.Err()
	if err != nil {
		return nil, err
	}
	return metrics, nil
}
