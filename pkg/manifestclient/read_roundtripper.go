package manifestclient

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	apidiscoveryv2 "k8s.io/api/apidiscovery/v2"
	"k8s.io/apimachinery/pkg/util/json"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/server"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

func init() {
	// This feature gate is needed to set requestInfo.LabelSelector
	utilruntime.Must(utilfeature.DefaultMutableFeatureGate.Set(fmt.Sprintf("%s=true", features.AuthorizeWithSelectors)))
}

type manifestRoundTripper struct {
	sourceFS fs.FS

	// requestInfoResolver is the same type constructed the same way as the kube-apiserver
	requestInfoResolver *apirequest.RequestInfoFactory

	lock            sync.RWMutex
	kindForResource map[schema.GroupVersionResource]kindData
}

type kindData struct {
	kind     schema.GroupVersionKind
	listKind schema.GroupVersionKind
	err      error
}

func newReadRoundTripper(content fs.FS) *manifestRoundTripper {
	return &manifestRoundTripper{
		sourceFS: content,
		requestInfoResolver: server.NewRequestInfoResolver(&server.Config{
			LegacyAPIGroupPrefixes: sets.NewString(server.DefaultLegacyAPIPrefix),
		}),
		kindForResource: make(map[schema.GroupVersionResource]kindData),
	}
}

// RoundTrip will allow performing read requests very similar to a kube-apiserver against a must-gather style directory.
// Only GETs.
// no watches. (maybe add watches
func (mrt *manifestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	requestInfo, err := mrt.requestInfoResolver.NewRequestInfo(req)
	if err != nil {
		return nil, fmt.Errorf("failed reading requestInfo: %w", err)
	}

	isDiscovery := isServerGroupResourceDiscovery(requestInfo.Path)
	if !requestInfo.IsResourceRequest && !isDiscovery {
		return nil, fmt.Errorf("non-resource requests are not supported by this implementation")
	}
	if len(requestInfo.Subresource) != 0 {
		return nil, fmt.Errorf("subresource %v is not supported by this implementation", requestInfo.Subresource)
	}
	if isDiscovery && requestInfo.Verb != "get" {
		// TODO handle group resource discovery
		return nil, fmt.Errorf("group resource discovery is not supported unless it is a GET request")
	}

	var returnBody []byte
	var returnErr error
	switch requestInfo.Verb {
	case "get":
		if isDiscovery {
			returnBody, returnErr = mrt.getGroupResourceDiscovery(requestInfo)
		} else {
			// TODO handle label and field selectors because single item lists are GETs
			returnBody, returnErr = mrt.get(requestInfo)
		}
	case "list":
		// TODO handle label and field selectors
		returnBody, returnErr = mrt.list(requestInfo)

	case "watch":
		// our watches do nothing.  We keep the connection alive (I  think), but nothing else.
		timeoutSecondsString := req.URL.Query().Get("timeoutSeconds")
		timeoutDuration := 10 * time.Minute
		if len(timeoutSecondsString) > 0 {
			currSeconds, err := strconv.ParseInt(timeoutSecondsString, 10, 32)
			if err != nil {
				returnErr = err
				break
			}
			timeoutDuration = time.Duration(currSeconds) * time.Second
		}
		resp := &http.Response{}
		resp.StatusCode = http.StatusOK
		resp.Status = http.StatusText(resp.StatusCode)
		resp.Body = newDelayedNothingReader(timeoutDuration)
		return resp, nil

	default:
		return nil, fmt.Errorf("verb %v is not supported by this implementation", requestInfo.Verb)
	}

	resp := &http.Response{}
	switch {
	case apierrors.IsNotFound(returnErr):
		resp.StatusCode = http.StatusNotFound
		resp.Status = http.StatusText(resp.StatusCode)
		resp.Body = io.NopCloser(bytes.NewBufferString(returnErr.Error()))
	case returnErr != nil:
		resp.StatusCode = http.StatusInternalServerError
		resp.Status = http.StatusText(resp.StatusCode)
		resp.Body = io.NopCloser(bytes.NewBufferString(returnErr.Error()))
	default:
		resp.StatusCode = http.StatusOK
		resp.Status = http.StatusText(resp.StatusCode)
		resp.Body = io.NopCloser(bytes.NewReader(returnBody))
		// We always return application/json. Avoid clients expecting proto for built-ins.
		resp.Header = make(http.Header)
		resp.Header.Set("Content-Type", "application/json")
	}

	return resp, nil
}

func newNotFound(requestInfo *apirequest.RequestInfo) error {
	return apierrors.NewNotFound(schema.GroupResource{
		Group:    requestInfo.APIGroup,
		Resource: requestInfo.Resource,
	}, requestInfo.Name)
}

// checking for /apis/<group>/<version>
// In this case we will return the list of resources for the group.
func isServerGroupResourceDiscovery(path string) bool {
	// Corev1 is a special case.
	if path == "/api/v1" {
		return true
	}
	if path == "/api" {
		return true
	}

	parts := strings.Split(path, "/")
	if len(parts) != 4 {
		return false
	}
	return parts[0] == "" && parts[1] == "apis"
}

//go:embed default-discovery
var defaultDiscovery embed.FS

func (mrt *manifestRoundTripper) getKindForResource(gvr schema.GroupVersionResource) (kindData, error) {
	mrt.lock.RLock()
	kindForGVR, ok := mrt.kindForResource[gvr]
	if ok {
		defer mrt.lock.RUnlock()
		return kindForGVR, kindForGVR.err
	}
	mrt.lock.RUnlock()

	mrt.lock.Lock()
	defer mrt.lock.Unlock()

	kindForGVR, ok = mrt.kindForResource[gvr]
	if ok {
		return kindForGVR, kindForGVR.err
	}

	discoveryPath := "/apis"
	if len(gvr.Group) == 0 {
		discoveryPath = "/api"
	}
	discoveryBytes, err := mrt.getGroupResourceDiscovery(&apirequest.RequestInfo{Path: discoveryPath})
	if err != nil {
		kindForGVR.err = fmt.Errorf("error reading discovery: %w", err)
		mrt.kindForResource[gvr] = kindForGVR
		return kindForGVR, kindForGVR.err
	}

	discoveryInfo := &apidiscoveryv2.APIGroupDiscoveryList{}
	if err := json.Unmarshal(discoveryBytes, discoveryInfo); err != nil {
		kindForGVR.err = fmt.Errorf("error unmarshalling discovery: %w", err)
		mrt.kindForResource[gvr] = kindForGVR
		return kindForGVR, kindForGVR.err
	}

	kindForGVR.err = fmt.Errorf("did not find kind for %v\n", gvr)
	for _, groupInfo := range discoveryInfo.Items {
		if groupInfo.Name != gvr.Group {
			continue
		}
		for _, versionInfo := range groupInfo.Versions {
			if versionInfo.Version != gvr.Version {
				continue
			}
			for _, resourceInfo := range versionInfo.Resources {
				if resourceInfo.Resource != gvr.Resource {
					continue
				}
				if resourceInfo.ResponseKind == nil {
					continue
				}
				kindForGVR.kind = schema.GroupVersionKind{
					Group:   gvr.Group,
					Version: gvr.Version,
					Kind:    resourceInfo.ResponseKind.Kind,
				}
				if len(resourceInfo.ResponseKind.Group) > 0 {
					kindForGVR.kind.Group = resourceInfo.ResponseKind.Group
				}
				if len(resourceInfo.ResponseKind.Version) > 0 {
					kindForGVR.kind.Version = resourceInfo.ResponseKind.Version
				}
				kindForGVR.listKind = schema.GroupVersionKind{
					Group:   kindForGVR.kind.Group,
					Version: kindForGVR.kind.Version,
					Kind:    resourceInfo.ResponseKind.Kind + "List",
				}
				kindForGVR.err = nil
				mrt.kindForResource[gvr] = kindForGVR
				return kindForGVR, kindForGVR.err
			}
		}
	}

	mrt.kindForResource[gvr] = kindForGVR
	return kindForGVR, kindForGVR.err
}
