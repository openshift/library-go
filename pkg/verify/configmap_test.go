package verify

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp"

	"github.com/openshift/library-go/pkg/verify/store/sigstore"
)

type VerifierAccessor interface {
	Verifiers() map[string]openpgp.EntityList
}

// roundTripper implements http.RoundTripper in memory.
type roundTripper struct {
	data     map[string]string
	delay    time.Duration
	requests []string
}

// RoundTrip implements http.RoundTripper.
func (rt *roundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx := request.Context()
	rt.requests = append(rt.requests, request.URL.String())

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(rt.delay):
	}

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

func Test_newFromConfigMapData(t *testing.T) {
	redhatData, err := ioutil.ReadFile(filepath.Join("testdata", "keyrings", "redhat.txt"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		data          map[string]string
		want          bool
		wantErr       bool
		wantVerifiers int
	}{
		{
			name:    "requires data",
			data:    nil,
			wantErr: true,
		},
		{
			name: "requires stores",
			data: map[string]string{
				"verifier-public-key-redhat": string(redhatData),
			},
			wantErr: true,
		},
		{
			name: "requires verifiers",
			data: map[string]string{
				"store-local": "file://../testdata/signatures",
			},
			wantErr: true,
		},
		{
			name: "loads valid configuration",
			data: map[string]string{
				"verifier-public-key-redhat": string(redhatData),
				"store-local":                "file://../testdata/signatures",
			},
			want:          true,
			wantVerifiers: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newFromConfigMapData("from_test", tt.data, sigstore.DefaultClient)
			if (err != nil) != tt.wantErr {
				t.Fatalf("newFromConfigMapData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil != tt.want {
				t.Fatal(got)
			}
			if err != nil {
				return
			}
			if got == nil {
				return
			}
			if len(got.Verifiers()) != tt.wantVerifiers {
				t.Fatalf("unexpected release verifier: %#v", got)
			}
		})
	}
}

func Test_newFromConfigMapData_slow_sigstore(t *testing.T) {
	redhatData, err := ioutil.ReadFile(filepath.Join("testdata", "keyrings", "redhat.txt"))
	if err != nil {
		t.Fatal(err)
	}

	rt := &roundTripper{
		delay: time.Second,
	}

	verifier, err := newFromConfigMapData("from_test", map[string]string{
		"store-example":              "https://example.com/signatures",
		"verifier-public-key-redhat": string(redhatData),
	}, func() (*http.Client, error) {
		return &http.Client{Transport: rt}, nil
	})

	if err != nil {
		t.Fatalf("newFromConfigMapData() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = verifier.Verify(ctx, "sha256:123")
	expected := regexp.MustCompile(`^unable to verify sha256:123 against keyrings: verifier-public-key-redhat$`)
	if !expected.MatchString(err.Error()) {
		t.Fatalf("expected %s, got %s", expected, err.Error())
	}

	wrapped := errors.Unwrap(err)
	expected = regexp.MustCompile(`^[[][0-9TZ:+-]*: Get "https://example.com/signatures/sha256=123/signature-1": context deadline exceeded, [0-9TZ:+-]*: context deadline exceeded]$`)
	if !expected.MatchString(wrapped.Error()) {
		t.Fatalf("expected %s, got %s", expected, wrapped.Error())
	}
}
