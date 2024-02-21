package endpointslices

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
)

func TestFilterHostNetwork(t *testing.T) {
	epInfo := EndpointSlicesInfo{
		EndpointSlice: discoveryv1.EndpointSlice{},
		Pods:          []corev1.Pod{{}},
		Serivce:       corev1.Service{},
	}
	tests := []struct {
		desc          string
		isHostNetwork bool
		expected      bool
	}{
		{
			desc:          "with-host-network",
			isHostNetwork: true,
			expected:      true,
		},
		{
			desc:          "without-host-network",
			isHostNetwork: false,
			expected:      false,
		},
	}
	for _, test := range tests {
		epInfo.Pods[0].Spec.HostNetwork = test.isHostNetwork
		res := FilterHostNetwork(epInfo)
		if res != test.expected {
			t.Fatalf("test %s failed. expected %v got %v", test.desc, test.expected, res)
		}
	}
}

func TestFilterServiceTypes(t *testing.T) {
	epInfo := EndpointSlicesInfo{
		EndpointSlice: discoveryv1.EndpointSlice{},
		Pods:          []corev1.Pod{},
		Serivce:       corev1.Service{},
	}
	tests := []struct {
		desc        string
		serviceType corev1.ServiceType
		expected    bool
	}{
		{
			desc:        "with-service-type-loadbalancer",
			serviceType: corev1.ServiceTypeLoadBalancer,
			expected:    true,
		},
		{
			desc:        "with-service-type-node-port",
			serviceType: corev1.ServiceTypeNodePort,
			expected:    true,
		},
		{
			desc:        "with-service-type-cluster-ip",
			serviceType: corev1.ServiceTypeClusterIP,
			expected:    false,
		},
		{
			desc:        "with-service-type-external-name",
			serviceType: corev1.ServiceTypeExternalName,
			expected:    false,
		},
	}
	for _, test := range tests {
		epInfo.Serivce.Spec.Type = test.serviceType
		res := FilterServiceTypes(epInfo)
		if res != test.expected {
			t.Fatalf("test %s failed. expected %v got %v", test.desc, test.expected, res)
		}
	}
}
