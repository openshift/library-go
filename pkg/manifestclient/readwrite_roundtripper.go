package manifestclient

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"net/http"
)

// Enter here and call `NewForConfigAndClient(&rest.Config{}, httpClient)`
func NewHTTPClient(mustGatherDir string) MutationTrackingClient {
	mutationTrackingRoundTripper := newReadWriteRoundTripper(newMustGatherReader(mustGatherDir))
	return &mutationTrackingClient{
		httpClient: &http.Client{
			Transport: mutationTrackingRoundTripper,
		},
		mutationTrackingRoundTripper: mutationTrackingRoundTripper,
	}
}

// Enter here and call `NewForConfigAndClient(&rest.Config{}, httpClient)`
func NewTestingHTTPClient(embedFS embed.FS, prefix string) MutationTrackingClient {
	mutationTrackingRoundTripper := newReadWriteRoundTripper(newPrefixedReader(embedFS, prefix))
	return &mutationTrackingClient{
		httpClient: &http.Client{
			Transport: mutationTrackingRoundTripper,
		},
		mutationTrackingRoundTripper: mutationTrackingRoundTripper,
	}
}

func NewTestingRoundTripper(embedFS embed.FS, prefix string) *readWriteRoundTripper {
	return newReadWriteRoundTripper(newPrefixedReader(embedFS, prefix))
}

func NewRoundTripper(mustGatherDir string) *readWriteRoundTripper {
	return newReadWriteRoundTripper(newMustGatherReader(mustGatherDir))
}

func newReadWriteRoundTripper(contentReader RawReader) *readWriteRoundTripper {
	return &readWriteRoundTripper{
		readDelegate:  newReadRoundTripper(contentReader),
		writeDelegate: newWriteRoundTripper(),
	}
}

type readWriteRoundTripper struct {
	readDelegate  *manifestRoundTripper
	writeDelegate *writeTrackingRoundTripper
}

type MutationTrackingRoundTripper interface {
	http.RoundTripper
	GetMutations() *AllActionsTracker[TrackedSerializedRequest]
}

type mutationTrackingClient struct {
	httpClient *http.Client

	mutationTrackingRoundTripper MutationTrackingRoundTripper
}

func (m mutationTrackingClient) GetHTTPClient() *http.Client {
	return m.httpClient
}

func (m mutationTrackingClient) GetMutations() *AllActionsTracker[TrackedSerializedRequest] {
	return m.mutationTrackingRoundTripper.GetMutations()
}

type MutationTrackingClient interface {
	GetHTTPClient() *http.Client
	GetMutations() *AllActionsTracker[TrackedSerializedRequest]
}

func (rt *readWriteRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.Method {
	case "GET", "HEAD":
		return rt.readDelegate.RoundTrip(req)
	case "POST", "PUT", "PATCH", "DELETE":
		return rt.writeDelegate.RoundTrip(req)
	default:
		resp := &http.Response{}
		resp.StatusCode = http.StatusInternalServerError
		resp.Status = http.StatusText(resp.StatusCode)
		resp.Body = io.NopCloser(bytes.NewBufferString(fmt.Sprintf("unhandled verb: %q", req.Method)))
		return resp, nil
	}
}

func (rt *readWriteRoundTripper) GetMutations() *AllActionsTracker[TrackedSerializedRequest] {
	return rt.writeDelegate.GetMutations()
}
