package manifestclient

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	apirequest "k8s.io/apiserver/pkg/endpoints/request"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/server"
)

type manifestRoundTripper struct {
	contentReader RawReader

	// requestInfoResolver is the same type constructed the same way as the kube-apiserver
	requestInfoResolver *apirequest.RequestInfoFactory
}

type RawReader interface {
	fs.FS
	fs.ReadFileFS
	fs.ReadDirFS
}

func newReadRoundTripper(contentReader RawReader) *manifestRoundTripper {
	return &manifestRoundTripper{
		contentReader: contentReader,
		requestInfoResolver: server.NewRequestInfoResolver(&server.Config{
			LegacyAPIGroupPrefixes: sets.NewString(server.DefaultLegacyAPIPrefix),
		}),
	}
}

type prefixedContentReader struct {
	embedFS embed.FS
	prefix  string
}

func newPrefixedReader(embedFS embed.FS, prefix string) RawReader {
	return &prefixedContentReader{
		embedFS: embedFS,
		prefix:  prefix,
	}
}

func (r *prefixedContentReader) Open(name string) (fs.File, error) {
	return r.embedFS.Open(filepath.Join(r.prefix, name))
}

func (r *prefixedContentReader) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(r.embedFS, filepath.Join(r.prefix, name))
}

func (r *prefixedContentReader) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(r.embedFS, filepath.Join(r.prefix, name))
}

type mustGatherReader struct {
	filesystem    fs.FS
	mustGatherDir string
}

func newMustGatherReader(mustGatherDir string) RawReader {
	return &mustGatherReader{
		filesystem:    os.DirFS(mustGatherDir),
		mustGatherDir: mustGatherDir,
	}
}

func (r *mustGatherReader) Open(name string) (fs.File, error) {
	return r.filesystem.Open(name)
}

func (r *mustGatherReader) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(r.filesystem, name)
}

func (r *mustGatherReader) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(r.filesystem, name)
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

	parts := strings.Split(path, "/")
	if len(parts) != 4 {
		return false
	}
	return parts[0] == "" && parts[1] == "apis"
}
