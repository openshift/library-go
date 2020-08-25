package sigstore

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"testing"
)

// RoundTripper implements http.RoundTripper in memory.
type RoundTripper struct {
	data     map[string]string
	requests []string
}

// RoundTrip implements http.RoundTripper.
func (rt *RoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	rt.requests = append(rt.requests, request.URL.String())

	data, ok := rt.data[request.URL.String()]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       ioutil.NopCloser(bytes.NewReader(nil)),
		}, nil
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewReader([]byte(data))),
	}, nil
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	uri, err := url.Parse("https://example.com/signatures")
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name               string
		data               map[string]string
		doneSignature      string
		doneError          error
		expectedRequests   []string
		expectedSignatures []string
		expectedError      *regexp.Regexp
	}{
		{
			name: "no signatures",
			expectedRequests: []string{
				"https://example.com/signatures/sha256=123/signature-1",
			},
		},
		{
			name: "three signatures",
			data: map[string]string{
				"https://example.com/signatures/sha256=123/signature-1": "sig-1",
				"https://example.com/signatures/sha256=123/signature-2": "sig-2",
				"https://example.com/signatures/sha256=123/signature-3": "sig-3",
			},
			expectedRequests: []string{
				"https://example.com/signatures/sha256=123/signature-1",
				"https://example.com/signatures/sha256=123/signature-2",
				"https://example.com/signatures/sha256=123/signature-3",
				"https://example.com/signatures/sha256=123/signature-4",
			},
			expectedSignatures: []string{"sig-1", "sig-2", "sig-3"},
		},
		{
			name: "early success",
			data: map[string]string{
				"https://example.com/signatures/sha256=123/signature-1": "sig-1",
				"https://example.com/signatures/sha256=123/signature-2": "sig-2",
				"https://example.com/signatures/sha256=123/signature-3": "sig-3",
			},
			doneSignature: "sig-2",
			expectedRequests: []string{
				"https://example.com/signatures/sha256=123/signature-1",
				"https://example.com/signatures/sha256=123/signature-2",
			},
			expectedSignatures: []string{"sig-1", "sig-2"},
		},
		{
			name: "skips empty signatures",
			data: map[string]string{
				"https://example.com/signatures/sha256=123/signature-1": "sig-1",
				"https://example.com/signatures/sha256=123/signature-2": "",
				"https://example.com/signatures/sha256=123/signature-3": "sig-3",
			},
			expectedRequests: []string{
				"https://example.com/signatures/sha256=123/signature-1",
				"https://example.com/signatures/sha256=123/signature-2",
				"https://example.com/signatures/sha256=123/signature-3",
				"https://example.com/signatures/sha256=123/signature-4",
			},
			expectedSignatures: []string{"sig-1", "sig-3"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rt := &RoundTripper{data: testCase.data}
			sigstore := &Store{
				URI: uri,
				HTTPClient: func() (*http.Client, error) {
					return &http.Client{Transport: rt}, nil
				},
			}

			var signatures []string
			err := sigstore.Signatures(ctx, "name", "sha256:123", func(ctx context.Context, signature []byte, errIn error) (done bool, err error) {
				if errIn != nil {
					return false, errIn
				}
				signatures = append(signatures, string(signature))
				if string(signature) == testCase.doneSignature {
					return true, testCase.doneError
				}
				return false, nil
			})
			if err == nil {
				if testCase.expectedError != nil {
					t.Fatalf("signatures succeeded when we expected %s", testCase.expectedError)
				}
			} else if testCase.expectedError == nil {
				t.Fatalf("signatures failed when we expected success: %v", err)
			} else if !testCase.expectedError.MatchString(err.Error()) {
				t.Fatalf("signatures failed with %v (expected %s)", err, testCase.expectedError)
			}

			if !reflect.DeepEqual(rt.requests, testCase.expectedRequests) {
				t.Fatalf("requests gathered %v when we expected %v", rt.requests, testCase.expectedRequests)
			}
			if !reflect.DeepEqual(signatures, testCase.expectedSignatures) {
				t.Fatalf("signatures gathered %v when we expected %v", signatures, testCase.expectedSignatures)
			}
		})
	}
}
