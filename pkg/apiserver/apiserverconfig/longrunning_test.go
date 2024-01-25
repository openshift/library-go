package apiserverconfig

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	buildv1 "github.com/openshift/api/build/v1"
	imagev1 "github.com/openshift/api/image/v1"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

func TestLongRunning(t *testing.T) {
	request := http.Request{
		URL:  &url.URL{Path: "/"},
		Host: "127.0.0.1",
	}
	scenarios := []struct {
		name        string
		requestInfo *apirequest.RequestInfo
		expected    bool
	}{
		{
			name:        "happy path",
			requestInfo: &apirequest.RequestInfo{},
			expected:    false,
		},
		{
			name:        "nil requestInfo",
			requestInfo: nil,
			expected:    false,
		},
		{
			name: "buildconfigs instantiatebinary",
			requestInfo: &apirequest.RequestInfo{
				APIGroup:    buildv1.GroupName,
				Resource:    "buildconfigs",
				Subresource: "instantiatebinary",
			},
			expected: true,
		},
		{
			name: "buildconfigs no subresource set",
			requestInfo: &apirequest.RequestInfo{
				APIGroup: buildv1.GroupName,
				Resource: "buildconfigs",
			},
			expected: false,
		},
		{
			name: "imagestreamimports",
			requestInfo: &apirequest.RequestInfo{
				APIGroup: imagev1.GroupName,
				Resource: "imagestreamimports",
			},
			expected: true,
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			actual := IsLongRunningRequest(&request, scenario.requestInfo)
			if actual != scenario.expected {
				t.Fatalf("expected %v, but was %v", scenario.expected, actual)
			}
		})
	}

	// verbs for kubeLongRunningFunc
	for verb := range longRunningVerbs {
		t.Run(fmt.Sprintf("verb %s", verb), func(t *testing.T) {
			requestInfo := &apirequest.RequestInfo{
				Verb: verb,
			}
			if IsLongRunningRequest(&request, requestInfo) == false {
				t.Fatalf("expected true, but was false")
			}
		})
	}

	// subresources for kubeLongRunningFunc
	for subresource := range longRunningSubresources {
		t.Run(fmt.Sprintf("subresource %s", subresource), func(t *testing.T) {
			requestInfo := &apirequest.RequestInfo{
				IsResourceRequest: true,
				Subresource:       subresource,
			}
			if IsLongRunningRequest(&request, requestInfo) == false {
				t.Fatalf("expected true, but was false")
			}
		})
	}
}
