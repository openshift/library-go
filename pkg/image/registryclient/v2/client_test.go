package registryclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/openshift/library-go/pkg/image/registryclient/v2/clienterrors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"k8s.io/client-go/rest"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest/manifestlist"
	"github.com/distribution/distribution/v3/manifest/schema2"
	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"

	imagereference "github.com/openshift/library-go/pkg/image/reference"
	"github.com/openshift/library-go/pkg/image/registryclient/v2/auth"
)

type mockRetriever struct {
	repo     distribution.Repository
	insecure bool
	err      error
}

func (r *mockRetriever) Repository(ctx context.Context, registry *url.URL, repoName string, insecure bool) (distribution.Repository, error) {
	r.insecure = insecure
	return r.repo, r.err
}

type mockRepository struct {
	repoErr, getErr, getByTagErr, getTagErr, tagErr, untagErr, allTagErr, err error

	blobs *mockBlobStore

	manifest distribution.Manifest
	tags     map[string]string
}

func (r *mockRepository) Name() string { return "test" }
func (r *mockRepository) Named() reference.Named {
	named, _ := reference.WithName("test")
	return named
}

func (r *mockRepository) Manifests(ctx context.Context, options ...distribution.ManifestServiceOption) (distribution.ManifestService, error) {
	return r, r.repoErr
}
func (r *mockRepository) Blobs(ctx context.Context) distribution.BlobStore { return r.blobs }
func (r *mockRepository) Exists(ctx context.Context, dgst digest.Digest) (bool, error) {
	return false, r.getErr
}
func (r *mockRepository) Get(ctx context.Context, dgst digest.Digest, options ...distribution.ManifestServiceOption) (distribution.Manifest, error) {
	for _, option := range options {
		if _, ok := option.(distribution.WithTagOption); ok {
			return r.manifest, r.getByTagErr
		}
	}
	return r.manifest, r.getErr
}
func (r *mockRepository) Delete(ctx context.Context, dgst digest.Digest) error {
	return fmt.Errorf("not implemented")
}
func (r *mockRepository) Put(ctx context.Context, manifest distribution.Manifest, options ...distribution.ManifestServiceOption) (digest.Digest, error) {
	return "", fmt.Errorf("not implemented")
}
func (r *mockRepository) Tags(ctx context.Context) distribution.TagService {
	return &mockTagService{repo: r}
}

type mockBlobStore struct {
	distribution.BlobStore

	blobs map[digest.Digest][]byte

	statErr, serveErr, openErr error
}

func (r *mockBlobStore) Stat(ctx context.Context, dgst digest.Digest) (distribution.Descriptor, error) {
	return distribution.Descriptor{}, r.statErr
}

func (r *mockBlobStore) ServeBlob(ctx context.Context, w http.ResponseWriter, req *http.Request, dgst digest.Digest) error {
	return r.serveErr
}

func (r *mockBlobStore) Open(ctx context.Context, dgst digest.Digest) (io.ReadSeekCloser, error) {
	return nil, r.openErr
}

func (r *mockBlobStore) Get(ctx context.Context, dgst digest.Digest) ([]byte, error) {
	b, exists := r.blobs[dgst]
	if !exists {
		return nil, distribution.ErrBlobUnknown
	}
	return b, nil
}

type mockTagService struct {
	distribution.TagService

	repo *mockRepository
}

func (r *mockTagService) Get(ctx context.Context, tag string) (distribution.Descriptor, error) {
	v, ok := r.repo.tags[tag]
	if !ok {
		return distribution.Descriptor{}, r.repo.getTagErr
	}
	dgst, err := digest.Parse(v)
	if err != nil {
		panic(err)
	}
	return distribution.Descriptor{Digest: dgst}, r.repo.getTagErr
}

func (r *mockTagService) Tag(ctx context.Context, tag string, desc distribution.Descriptor) error {
	r.repo.tags[tag] = desc.Digest.String()
	return r.repo.tagErr
}

func (r *mockTagService) Untag(ctx context.Context, tag string) error {
	if _, ok := r.repo.tags[tag]; ok {
		delete(r.repo.tags, tag)
	}
	return r.repo.untagErr
}

func (r *mockTagService) All(ctx context.Context) (res []string, err error) {
	err = r.repo.allTagErr
	for tag := range r.repo.tags {
		res = append(res, tag)
	}
	return
}

func (r *mockTagService) Lookup(ctx context.Context, digest distribution.Descriptor) ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestPing(t *testing.T) {
	retriever := NewContext(http.DefaultTransport, http.DefaultTransport).WithCredentials(NoCredentials)

	fn404 := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }
	var fn http.HandlerFunc
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if fn != nil {
			fn(w, r)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	uri, _ := url.Parse(server.URL)

	testCases := []struct {
		name     string
		uri      url.URL
		expectV2 bool
		fn       http.HandlerFunc
	}{
		{name: "http only", uri: url.URL{Scheme: "http", Host: uri.Host}, expectV2: false, fn: fn404},
		{name: "https only", uri: url.URL{Scheme: "https", Host: uri.Host}, expectV2: false, fn: fn404},
		{
			name:     "403",
			uri:      url.URL{Scheme: "https", Host: uri.Host},
			expectV2: true,
			fn: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.WriteHeader(403)
					return
				}
			},
		},
		{
			name:     "401",
			uri:      url.URL{Scheme: "https", Host: uri.Host},
			expectV2: true,
			fn: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.WriteHeader(401)
					return
				}
			},
		},
		{
			name:     "200",
			uri:      url.URL{Scheme: "https", Host: uri.Host},
			expectV2: true,
			fn: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.WriteHeader(200)
					return
				}
			},
		},
		{
			name:     "has header but 500",
			uri:      url.URL{Scheme: "https", Host: uri.Host},
			expectV2: true,
			fn: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
					w.WriteHeader(500)
					return
				}
			},
		},
		{
			name:     "no header, 500",
			uri:      url.URL{Scheme: "https", Host: uri.Host},
			expectV2: false,
			fn: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/" {
					w.WriteHeader(500)
					return
				}
			},
		},
	}

	for _, test := range testCases {
		fn = test.fn
		_, err := retriever.ping(test.uri, true, retriever.InsecureTransport)
		if (err != nil && strings.Contains(err.Error(), "does not support v2 API")) == test.expectV2 {
			t.Errorf("%s: Expected ErrNotV2Registry, got %v", test.name, err)
		}
	}
}

var unlimited = rate.NewLimiter(rate.Inf, 100)

type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary" }
func (temporaryError) Timeout() bool   { return false }
func (temporaryError) Temporary() bool { return true }

func TestShouldRetry(t *testing.T) {
	r := NewLimitedRetryRepository(imagereference.DockerImageReference{}, nil, 1, unlimited).(*retryRepository)
	sleeps := 0
	r.sleepFn = func(time.Duration) { sleeps++ }

	// nil error doesn't consume retries
	if r.shouldRetry(0, nil) {
		t.Fatal(r)
	}

	// normal error doesn't consume retries
	if r.shouldRetry(0, fmt.Errorf("error")) {
		t.Fatal(r)
	}

	// docker error doesn't consume retries
	if r.shouldRetry(0, errcode.ErrorCodeDenied) {
		t.Fatal(r)
	}
	if sleeps != 0 {
		t.Fatal(sleeps)
	}

	now := time.Unix(1, 0)
	nowFn = func() time.Time {
		return now
	}
	// should retry a temporary error
	r = NewLimitedRetryRepository(imagereference.DockerImageReference{}, nil, 1, unlimited).(*retryRepository)
	sleeps = 0
	r.sleepFn = func(time.Duration) { sleeps++ }
	if !r.shouldRetry(0, temporaryError{}) {
		t.Fatal(r)
	}
	if r.shouldRetry(1, temporaryError{}) {
		t.Fatal(r)
	}
	if sleeps != 1 {
		t.Fatal(sleeps)
	}
}

func TestRetryFailure(t *testing.T) {
	sleeps := 0
	sleepFn := func(time.Duration) { sleeps++ }

	ctx := context.Background()
	// do not retry on Manifests()
	repo := &mockRepository{repoErr: fmt.Errorf("does not support v2 API")}
	r := NewLimitedRetryRepository(imagereference.DockerImageReference{}, repo, 1, unlimited).(*retryRepository)
	sleeps = 0
	r.sleepFn = sleepFn
	if m, err := r.Manifests(ctx); m != nil || err != repo.repoErr || r.retries != 1 {
		t.Fatalf("unexpected: %v %v %#v", m, err, r)
	}

	// do not retry on Manifests()
	repo = &mockRepository{repoErr: temporaryError{}}
	r = NewLimitedRetryRepository(imagereference.DockerImageReference{}, repo, 4, unlimited).(*retryRepository)
	sleeps = 0
	r.sleepFn = sleepFn
	if m, err := r.Manifests(ctx); m != nil || err != repo.repoErr || r.retries != 4 {
		t.Fatalf("unexpected: %v %v %#v", m, err, r)
	}

	// do not retry on non standard errors
	repo = &mockRepository{getErr: fmt.Errorf("does not support v2 API")}
	r = NewLimitedRetryRepository(imagereference.DockerImageReference{}, repo, 4, unlimited).(*retryRepository)
	sleeps = 0
	r.sleepFn = sleepFn
	m, err := r.Manifests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, digest.Digest("foo")); err != repo.getErr || r.retries != 4 {
		t.Fatalf("unexpected: %v %v %#v", m, err, r)
	}

	// verify docker known errors
	repo = &mockRepository{
		getErr: temporaryError{},
		blobs: &mockBlobStore{
			serveErr: errcode.ErrorCodeTooManyRequests.WithDetail(struct{}{}),
			statErr:  errcode.ErrorCodeUnavailable.WithDetail(struct{}{}),
			// not retriable
			openErr: errcode.ErrorCodeUnknown.WithDetail(struct{}{}),
		},
	}
	r = NewLimitedRetryRepository(imagereference.DockerImageReference{}, repo, 4, unlimited).(*retryRepository)
	sleeps = 0
	r.sleepFn = sleepFn
	if m, err = r.Manifests(ctx); err != nil {
		t.Fatal(err)
	}
	r.retries = 1
	if _, err := m.Get(ctx, digest.Digest("foo")); err != repo.getErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 2
	if m, err := m.Exists(ctx, "foo"); m || err != repo.getErr {
		t.Fatalf("unexpected: %v %v %#v", m, err, r)
	}
	if sleeps != 3 {
		t.Fatal(sleeps)
	}

	sleeps = 0
	r.retries = 1
	b := r.Blobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Stat(ctx, digest.Digest("x")); err != repo.blobs.statErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 2
	if err := b.ServeBlob(ctx, nil, nil, digest.Digest("foo")); err != repo.blobs.serveErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 4
	if _, err := b.Open(ctx, digest.Digest("foo")); err != repo.blobs.openErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	// Open did not retry
	if sleeps != 3 {
		t.Fatal(sleeps)
	}

	// verify unknown client errors
	repo = &mockRepository{
		getErr: temporaryError{},
		blobs: &mockBlobStore{
			serveErr: &clienterrors.UnexpectedHTTPResponseError{StatusCode: http.StatusTooManyRequests},
			statErr:  &clienterrors.UnexpectedHTTPResponseError{StatusCode: http.StatusServiceUnavailable},
			openErr:  &clienterrors.UnexpectedHTTPResponseError{StatusCode: http.StatusInternalServerError},
		},
	}
	r = NewLimitedRetryRepository(imagereference.DockerImageReference{}, repo, 4, unlimited).(*retryRepository)
	sleeps = 0
	r.sleepFn = sleepFn
	if m, err = r.Manifests(ctx); err != nil {
		t.Fatal(err)
	}
	r.retries = 1
	if _, err := m.Get(ctx, digest.Digest("foo")); err != repo.getErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 2
	if m, err := m.Exists(ctx, "foo"); m || err != repo.getErr {
		t.Fatalf("unexpected: %v %v %#v", m, err, r)
	}
	if sleeps != 3 {
		t.Fatal(sleeps)
	}

	sleeps = 0
	r.retries = 1
	b = r.Blobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Stat(ctx, digest.Digest("x")); err != repo.blobs.statErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 2
	if err := b.ServeBlob(ctx, nil, nil, digest.Digest("foo")); err != repo.blobs.serveErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 4
	if _, err := b.Open(ctx, digest.Digest("foo")); err != repo.blobs.openErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	// Open did not retry
	if sleeps != 7 {
		t.Fatal(sleeps)
	}

	// verify more unknown client errors
	repo = &mockRepository{
		getErr: temporaryError{},
		blobs: &mockBlobStore{
			serveErr: &clienterrors.UnexpectedHTTPResponseError{StatusCode: http.StatusBadGateway},
			statErr:  &clienterrors.UnexpectedHTTPResponseError{StatusCode: http.StatusGatewayTimeout},
			openErr:  &clienterrors.UnexpectedHTTPResponseError{StatusCode: http.StatusInternalServerError},
		},
	}
	r = NewLimitedRetryRepository(imagereference.DockerImageReference{}, repo, 4, unlimited).(*retryRepository)
	sleeps = 0
	r.sleepFn = sleepFn
	if m, err = r.Manifests(ctx); err != nil {
		t.Fatal(err)
	}
	r.retries = 1
	if _, err := m.Get(ctx, digest.Digest("foo")); err != repo.getErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 2
	if m, err := m.Exists(ctx, "foo"); m || err != repo.getErr {
		t.Fatalf("unexpected: %v %v %#v", m, err, r)
	}
	if sleeps != 3 {
		t.Fatal(sleeps)
	}

	sleeps = 0
	r.retries = 1
	b = r.Blobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Stat(ctx, digest.Digest("x")); err != repo.blobs.statErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 2
	if err := b.ServeBlob(ctx, nil, nil, digest.Digest("foo")); err != repo.blobs.serveErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 4
	if _, err := b.Open(ctx, digest.Digest("foo")); err != repo.blobs.openErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	// Open did not retry
	if sleeps != 7 {
		t.Fatal(sleeps)
	}

	// retry with temporary errors
	repo = &mockRepository{
		getErr: temporaryError{},
		blobs: &mockBlobStore{
			serveErr: temporaryError{},
			statErr:  temporaryError{},
			openErr:  temporaryError{},
		},
	}
	r = NewLimitedRetryRepository(imagereference.DockerImageReference{}, repo, 4, unlimited).(*retryRepository)
	sleeps = 0
	r.sleepFn = sleepFn
	if m, err = r.Manifests(ctx); err != nil {
		t.Fatal(err)
	}
	r.retries = 1
	if _, err := m.Get(ctx, digest.Digest("foo")); err != repo.getErr {
		t.Fatalf("unexpected: %v %#v", err, r)
	}
	r.retries = 2
	if m, err := m.Exists(ctx, "foo"); m || err != repo.getErr {
		t.Fatalf("unexpected: %v %v %#v", m, err, r)
	}
	if sleeps != 3 {
		t.Fatal(sleeps)
	}
}

func Test_verifyManifest_Get(t *testing.T) {
	tests := []struct {
		name     string
		dgst     digest.Digest
		err      error
		manifest distribution.Manifest
		options  []distribution.ManifestServiceOption
		want     distribution.Manifest
		wantErr  bool
	}{
		{
			dgst:     payload1Digest,
			manifest: &fakeManifest{payload: []byte(payload1)},
			want:     &fakeManifest{payload: []byte(payload1)},
		},
		{
			dgst:     payload2Digest,
			manifest: &fakeManifest{payload: []byte(payload2)},
			want:     &fakeManifest{payload: []byte(payload2)},
		},
		{
			dgst:     payload1Digest,
			manifest: &fakeManifest{payload: []byte(payload2)},
			wantErr:  true,
		},
		{
			dgst:     payload1Digest,
			manifest: &fakeManifest{payload: []byte(payload1), err: fmt.Errorf("unknown")},
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := &fakeManifestService{err: tt.err, manifest: tt.manifest}
			m := manifestServiceVerifier{
				ManifestService: ms,
			}
			ctx := context.Background()
			got, err := m.Get(ctx, tt.dgst, tt.options...)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyManifest.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("verifyManifest.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_verifyManifest_Put(t *testing.T) {
	tests := []struct {
		name     string
		dgst     digest.Digest
		err      error
		manifest distribution.Manifest
		options  []distribution.ManifestServiceOption
		want     digest.Digest
		wantErr  string
	}{
		{
			dgst:     payload1Digest,
			manifest: &fakeManifest{payload: []byte(payload1)},
			want:     payload1Digest,
		},
		{
			dgst:     payload2Digest,
			manifest: &fakeManifest{payload: []byte(payload2)},
			want:     payload2Digest,
		},
		{
			dgst:     payload1Digest,
			manifest: &fakeManifest{payload: []byte(payload2)},
			wantErr:  "the manifest retrieved with digest sha256:59685d14054198fee6005106a66462a924cabe21f4b0c7c1fdf4da95ccee52bd does not match the digest calculated from the content sha256:b79e87ded1ea5293efe92bdb3caa9b7212cfa7c98aafb7c1c568d11d43519968",
		},
		{
			err:      fmt.Errorf("put error"),
			manifest: &fakeManifest{payload: []byte(payload2)},
			wantErr:  "put error",
		},
		{
			manifest: &fakeManifest{payload: []byte(payload2)},
		},
		{
			manifest: &fakeManifest{payload: []byte(payload1), err: fmt.Errorf("unknown")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := &fakeManifestService{err: tt.err, manifest: tt.manifest, digest: tt.dgst}
			m := manifestServiceVerifier{
				ManifestService: ms,
			}
			ctx := context.Background()
			got, err := m.Put(ctx, tt.manifest, tt.options...)
			if len(tt.wantErr) > 0 && err != nil && !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("verifyManifest.Get() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (err != nil) != (len(tt.wantErr) > 0) {
				t.Fatalf("verifyManifest.Get() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("verifyManifest.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

const (
	payload1 = `{"some":"content"}`
	payload2 = `{"some":"content"} `
)

var (
	payload1Digest = digest.SHA256.FromString(payload1)
	payload2Digest = digest.SHA256.FromString(payload2)
)

type fakeManifest struct {
	mediaType string
	payload   []byte
	err       error
}

func (m *fakeManifest) References() []distribution.Descriptor {
	panic("not implemented")
}

func (m *fakeManifest) Payload() (mediaType string, payload []byte, err error) {
	return m.mediaType, m.payload, m.err
}

type fakeManifestService struct {
	digest   digest.Digest
	manifest distribution.Manifest
	err      error
}

func (s *fakeManifestService) Exists(ctx context.Context, dgst digest.Digest) (bool, error) {
	panic("not implemented")
}

func (s *fakeManifestService) Get(ctx context.Context, dgst digest.Digest, options ...distribution.ManifestServiceOption) (distribution.Manifest, error) {
	return s.manifest, s.err
}

func (s *fakeManifestService) Put(ctx context.Context, manifest distribution.Manifest, options ...distribution.ManifestServiceOption) (digest.Digest, error) {
	return s.digest, s.err
}

func (s *fakeManifestService) Delete(ctx context.Context, dgst digest.Digest) error {
	panic("not implemented")
}

func Test_blobStoreVerifier_Get(t *testing.T) {
	tests := []struct {
		name    string
		bytes   []byte
		err     error
		dgst    digest.Digest
		want    []byte
		wantErr bool
	}{
		{
			dgst:  payload1Digest,
			bytes: []byte(payload1),
			want:  []byte(payload1),
		},
		{
			dgst:  payload2Digest,
			bytes: []byte(payload2),
			want:  []byte(payload2),
		},
		{
			dgst:    payload1Digest,
			bytes:   []byte(payload2),
			wantErr: true,
		},
		{
			dgst:    payload1Digest,
			bytes:   []byte(payload1),
			err:     fmt.Errorf("unknown"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := &fakeBlobStore{err: tt.err, bytes: tt.bytes}
			b := blobStoreVerifier{
				BlobStore: bs,
			}
			ctx := context.Background()
			got, err := b.Get(ctx, tt.dgst)
			if (err != nil) != tt.wantErr {
				t.Errorf("blobStoreVerifier.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("blobStoreVerifier.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_blobStoreVerifier_Open(t *testing.T) {
	tests := []struct {
		name    string
		bytes   []byte
		err     error
		dgst    digest.Digest
		want    func(t *testing.T, got io.ReadSeekCloser)
		wantErr bool
	}{
		{
			dgst:  payload1Digest,
			bytes: []byte(payload1),
			want: func(t *testing.T, got io.ReadSeekCloser) {
				data, err := io.ReadAll(got)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal([]byte(payload1), data) {
					t.Fatalf("contents not equal: %s", hex.Dump(data))
				}
			},
		},
		{
			dgst:  payload2Digest,
			bytes: []byte(payload2),
			want: func(t *testing.T, got io.ReadSeekCloser) {
				data, err := io.ReadAll(got)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal([]byte(payload2), data) {
					t.Fatalf("contents not equal: %s", hex.Dump(data))
				}
			},
		},
		{
			dgst:  payload1Digest,
			bytes: []byte(payload2),
			want: func(t *testing.T, got io.ReadSeekCloser) {
				data, err := io.ReadAll(got)
				if err == nil || !strings.Contains(err.Error(), "content integrity error") || !strings.Contains(err.Error(), payload2Digest.String()) {
					t.Fatal(err)
				}
				if !bytes.Equal([]byte(payload2), data) {
					t.Fatalf("contents not equal: %s", hex.Dump(data))
				}
			},
		},
		{
			dgst:  payload1Digest,
			bytes: []byte(payload2),
			want: func(t *testing.T, got io.ReadSeekCloser) {
				_, err := got.Seek(0, 0)
				if err == nil || err.Error() != "invoked seek" {
					t.Fatal(err)
				}
				data, err := io.ReadAll(got)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal([]byte(payload2), data) {
					t.Fatalf("contents not equal: %s", hex.Dump(data))
				}
			},
		},
		{
			dgst:    payload1Digest,
			bytes:   []byte(payload1),
			err:     fmt.Errorf("unknown"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := &fakeBlobStore{err: tt.err, bytes: tt.bytes}
			b := blobStoreVerifier{
				BlobStore: bs,
			}
			ctx := context.Background()
			got, err := b.Open(ctx, tt.dgst)
			if (err != nil) != tt.wantErr {
				t.Errorf("blobStoreVerifier.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			tt.want(t, got)
		})
	}
}

type fakeSeekCloser struct {
	*bytes.Buffer
}

func (f fakeSeekCloser) Seek(offset int64, whence int) (int64, error) {
	return 0, fmt.Errorf("invoked seek")
}

func (f fakeSeekCloser) Close() error {
	return fmt.Errorf("not implemented")
}

type fakeBlobStore struct {
	bytes []byte
	err   error
}

func (s *fakeBlobStore) Stat(ctx context.Context, dgst digest.Digest) (distribution.Descriptor, error) {
	panic("not implemented")
}

func (s *fakeBlobStore) Get(ctx context.Context, dgst digest.Digest) ([]byte, error) {
	return s.bytes, s.err
}

func (s *fakeBlobStore) Open(ctx context.Context, dgst digest.Digest) (io.ReadSeekCloser, error) {
	return fakeSeekCloser{bytes.NewBuffer(s.bytes)}, s.err
}

func (s *fakeBlobStore) Put(ctx context.Context, mediaType string, p []byte) (distribution.Descriptor, error) {
	panic("not implemented")
}

func (s *fakeBlobStore) Create(ctx context.Context, options ...distribution.BlobCreateOption) (distribution.BlobWriter, error) {
	panic("not implemented")
}

func (s *fakeBlobStore) Resume(ctx context.Context, id string) (distribution.BlobWriter, error) {
	panic("not implemented")
}

func (s *fakeBlobStore) ServeBlob(ctx context.Context, w http.ResponseWriter, r *http.Request, dgst digest.Digest) error {
	panic("not implemented")
}

func (s *fakeBlobStore) Delete(ctx context.Context, dgst digest.Digest) error {
	panic("not implemented")
}

type fakeAlternateBlobStrategy struct {
	FirstAlternates []imagereference.DockerImageReference
	FirstErr        error

	FailureAlternates []imagereference.DockerImageReference
	FailureErr        error
}

func (s *fakeAlternateBlobStrategy) FirstRequest(ctx context.Context, locator imagereference.DockerImageReference) (alternateRepositories []imagereference.DockerImageReference, err error) {
	return s.FirstAlternates, s.FirstErr
}

func (s *fakeAlternateBlobStrategy) OnFailure(ctx context.Context, locator imagereference.DockerImageReference) (alternateRepositories []imagereference.DockerImageReference, err error) {
	return s.FailureAlternates, s.FailureErr
}

type fakeAlternateBlobStrategyFuncs struct {
	FirstRequestFunc func(ctx context.Context, locator imagereference.DockerImageReference) (alternateRepositories []imagereference.DockerImageReference, err error)
	OnFailureFunc    func(ctx context.Context, locator imagereference.DockerImageReference) (alternateRepositories []imagereference.DockerImageReference, err error)
}

func (s *fakeAlternateBlobStrategyFuncs) FirstRequest(ctx context.Context, locator imagereference.DockerImageReference) (alternateRepositories []imagereference.DockerImageReference, err error) {
	return s.FirstRequestFunc(ctx, locator)
}

func (s *fakeAlternateBlobStrategyFuncs) OnFailure(ctx context.Context, locator imagereference.DockerImageReference) (alternateRepositories []imagereference.DockerImageReference, err error) {
	return s.OnFailureFunc(ctx, locator)
}

func TestMirroredRegistry_BlobGet(t *testing.T) {
	// HACK for debugging, remove
	// klog.InitFlags(flag.CommandLine)
	// cliflag.InitFlags()
	// flag.CommandLine.Lookup("v").Value.Set("10")

	rt, err := rest.TransportFor(&rest.Config{})
	if err != nil {
		t.Fatal(err)
	}
	insecureRT, err := rest.TransportFor(&rest.Config{TLSClientConfig: rest.TLSClientConfig{Insecure: true}})
	if err != nil {
		t.Fatal(err)
	}
	c := NewContext(rt, insecureRT)

	r, err := c.Repository(context.Background(), &url.URL{Host: "registry-1.docker.io"}, "library/postgres", false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := r.Blobs(context.Background()).Get(context.Background(), digest.Digest("sha256:bb3d505cd0cb857db56eae10f575eb036b898adf0ca80ff0b7934b6e01adb92c"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("Expected data to be present")
	}

	c.Alternates = &fakeAlternateBlobStrategyFuncs{
		FirstRequestFunc: func(ctx context.Context, locator imagereference.DockerImageReference) (alternateRepositories []imagereference.DockerImageReference, err error) {
			if locator.Exact() != "quay.io/test.me/other" {
				t.Errorf("unexpected locator: %#+v", locator)
			}
			return []imagereference.DockerImageReference{
				{Registry: "quay.io", Namespace: "library", Name: "postgres"},
				{Registry: "docker.io", Namespace: "library", Name: "postgres"},
			}, nil
		},
	}
	r, err = c.Repository(context.Background(), &url.URL{Host: "quay.io"}, "test.me/other", false)
	if err != nil {
		t.Fatal(err)
	}
	otherData, err := r.Blobs(context.Background()).Get(context.Background(), digest.Digest("sha256:bb3d505cd0cb857db56eae10f575eb036b898adf0ca80ff0b7934b6e01adb92c"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("Expected data to be present")
	}
	if !bytes.Equal(data, otherData) {
		t.Fatalf("Mirror and non mirror request did not match")
	}
}

func TestMirroredRegistry_ManifestGet(t *testing.T) {
	opt := distribution.WithManifestMediaTypes([]string{
		manifestlist.MediaTypeManifestList,
		schema2.MediaTypeManifest,
	})

	rt, err := rest.TransportFor(&rest.Config{})
	if err != nil {
		t.Fatal(err)
	}
	insecureRT, err := rest.TransportFor(&rest.Config{TLSClientConfig: rest.TLSClientConfig{Insecure: true}})
	if err != nil {
		t.Fatal(err)
	}
	c := NewContext(rt, insecureRT)

	t.Logf("original request")

	r, err := c.Repository(context.Background(), &url.URL{Host: "registry-1.docker.io"}, "library/postgres", false)
	if err != nil {
		t.Fatal(err)
	}
	m, err := r.Manifests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := m.Get(context.Background(), digest.Digest("sha256:b94ab3a31950e7d25654d024044ac217c2b3a94eff426e3415424c1c16ca3fe6"), opt)
	if err != nil {
		t.Fatal(err)
	}
	if manifest == nil {
		t.Fatal("Expected data to be present")
	}

	t.Logf("alternate FirstRequest")

	c.Alternates = &fakeAlternateBlobStrategy{
		FirstAlternates: []imagereference.DockerImageReference{
			{Registry: "quay.io", Namespace: "library", Name: "postgres"},
			{Registry: "docker.io", Namespace: "library", Name: "postgres"},
		},
	}
	r, err = c.Repository(context.Background(), &url.URL{Host: "quay.io"}, "test/other", false)
	if err != nil {
		t.Fatal(err)
	}
	m, err = r.Manifests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	otherManifest, err := m.Get(context.Background(), digest.Digest("sha256:b94ab3a31950e7d25654d024044ac217c2b3a94eff426e3415424c1c16ca3fe6"), opt)
	if err != nil {
		t.Fatal(err)
	}

	if otherManifest == nil {
		t.Fatal("Expected data to be present")
	}
	if !reflect.DeepEqual(manifest, otherManifest) {
		t.Fatalf("Mirror and non mirror request did not match")
	}

	mwl, ok := m.(ManifestWithLocationService)
	if !ok {
		t.Fatalf("Expected service to implement location retrieval")
	}

	otherManifest, ref, err := mwl.GetWithLocation(context.Background(), digest.Digest("sha256:b94ab3a31950e7d25654d024044ac217c2b3a94eff426e3415424c1c16ca3fe6"), opt)
	if err != nil {
		t.Fatal(err)
	}
	if otherManifest == nil {
		t.Fatal("Expected data to be present")
	}
	if !reflect.DeepEqual(manifest, otherManifest) {
		t.Fatalf("Mirror and non mirror request did not match")
	}
	if !reflect.DeepEqual(ref, imagereference.DockerImageReference{Registry: "docker.io", Namespace: "library", Name: "postgres"}) {
		t.Fatalf("Unexpected reference: %#v", ref)
	}

	t.Logf("alternate OnFailure")

	c.Alternates = &fakeAlternateBlobStrategy{
		FailureAlternates: []imagereference.DockerImageReference{
			{Registry: "quay.io", Namespace: "library", Name: "postgres"},
			{Registry: "docker.io", Namespace: "library", Name: "postgres"},
		},
	}
	r, err = c.Repository(context.Background(), &url.URL{Host: "quay.io"}, "test/other", false)
	if err != nil {
		t.Fatal(err)
	}
	m, err = r.Manifests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mwl, ok = m.(ManifestWithLocationService)
	if !ok {
		t.Fatalf("Expected service to implement location retrieval")
	}
	secondManifest, secondRef, err := mwl.GetWithLocation(context.Background(), digest.Digest("sha256:b94ab3a31950e7d25654d024044ac217c2b3a94eff426e3415424c1c16ca3fe6"), opt)
	if err != nil {
		t.Fatal(err)
	}

	if secondManifest == nil {
		t.Fatal("Expected data to be present")
	}
	if !reflect.DeepEqual(manifest, secondManifest) {
		t.Fatalf("Mirror and non mirror request did not match")
	}
	if !reflect.DeepEqual(secondRef, imagereference.DockerImageReference{Registry: "docker.io", Namespace: "library", Name: "postgres"}) {
		t.Fatalf("Unexpected reference: %#v", ref)
	}
}

func TestMirroredRegistry_InvalidManifest(t *testing.T) {
	opt := distribution.WithManifestMediaTypes([]string{
		manifestlist.MediaTypeManifestList,
		schema2.MediaTypeManifest,
	})

	rt, err := rest.TransportFor(&rest.Config{})
	if err != nil {
		t.Fatal(err)
	}
	insecureRT, err := rest.TransportFor(&rest.Config{TLSClientConfig: rest.TLSClientConfig{Insecure: true}})
	if err != nil {
		t.Fatal(err)
	}
	c := NewContext(rt, insecureRT)

	r, err := c.Repository(context.Background(), &url.URL{Host: "registry-1.docker.io"}, "library/postgres", false)
	if err != nil {
		t.Fatal(err)
	}
	m, err := r.Manifests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Get(context.Background(), digest.Digest("@sha256:deadbeef00000000000000000000000000000000000000000000000000000000"), opt)
	if err == nil {
		t.Fatal("Expected manifest reading error")
	}
}

func TestMirroredRegistry_AlternateErrors(t *testing.T) {
	opt := distribution.WithManifestMediaTypes([]string{
		manifestlist.MediaTypeManifestList,
		schema2.MediaTypeManifest,
	})

	rt, err := rest.TransportFor(&rest.Config{})
	if err != nil {
		t.Fatal(err)
	}
	insecureRT, err := rest.TransportFor(&rest.Config{TLSClientConfig: rest.TLSClientConfig{Insecure: true}})
	if err != nil {
		t.Fatal(err)
	}

	c := NewContext(rt, insecureRT)
	c.Alternates = &fakeAlternateBlobStrategy{
		FirstErr: fmt.Errorf("icsp error"),
	}

	t.Logf("alternate FirstRequest error")

	r, err := c.Repository(context.Background(), &url.URL{Host: "quay.io"}, "test/other", false)
	if err != nil {
		t.Fatal(err)
	}
	m, err := r.Manifests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Get(context.Background(), digest.Digest("sha256:b94ab3a31950e7d25654d024044ac217c2b3a94eff426e3415424c1c16ca3fe6"), opt)
	if err == nil || !strings.Contains(err.Error(), "icsp error") {
		t.Fatalf("Expected 'icsp error', got %v", err)
	}

	t.Logf("alternate OnFailure error")

	c.Alternates = &fakeAlternateBlobStrategy{
		FailureErr: fmt.Errorf("icsp failure error"),
	}

	r, err = c.Repository(context.Background(), &url.URL{Host: "quay.io"}, "test/other", false)
	if err != nil {
		t.Fatal(err)
	}
	m, err = r.Manifests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Get(context.Background(), digest.Digest("sha256:b94ab3a31950e7d25654d024044ac217c2b3a94eff426e3415424c1c16ca3fe6"), opt)
	if err == nil || !strings.Contains(err.Error(), "icsp failure error") {
		t.Fatalf("Expected 'icsp failure error' got %v", err)
	}
}

// staticCreds implements auth.CredentialStore and returns always the same user and pass pair,
// regardless of the registry URL.
type staticCreds struct {
	registry string
	user     string
	pass     string
}

// Basic is called when obtaining user/pass pair for a given registry URL. staticCreds returns
// always the same data.
func (s staticCreds) Basic(*url.URL) (string, string) {
	return s.user, s.pass
}

// RefreshToken is here so staticCreds complies with auth.CredentialStore.
func (s staticCreds) RefreshToken(*url.URL, string) string {
	return ""
}

// SetRefreshToken is here so staticCreds complies with auth.CredentialStore.
func (s staticCreds) SetRefreshToken(realm *url.URL, service, token string) {
}

// fakeCredentialStoreFactory groups a bunch of static credentials. It implements the interface
// CredentialsFactory. Credentials are filtered by staticCreds.registry property.
type fakeCredentialStoreFactory struct {
	auths []staticCreds
}

// CredentialStoreFor filters the list of credentials. Looks for a suitable authentication for
// provided image. Panics if no authentication was found.
func (f *fakeCredentialStoreFactory) CredentialStoreFor(image string) auth.CredentialStore {
	for _, auth := range f.auths {
		if auth.registry == image {
			return auth
		}
	}
	panic("unable to locate auth")
}

// registryAuthMock is a multiplexer that mimics what happen in a registry during the initial
// authentication process. This entity keeps track of all authentication attempts made.
type registryAuthMock struct {
	attemptedAuths []staticCreds
}

// Reset clears up the mock. Removes any previously attempted authentication.
func (m *registryAuthMock) Reset() {
	m.attemptedAuths = nil
}

// ping returns an StatusUnauthorized and redirects requests to /v2/auth endpoint.
func (m *registryAuthMock) ping(w http.ResponseWriter, r *http.Request) {
	authHeader := fmt.Sprintf(`Bearer realm="https://%s/v2/auth"`, r.Host)
	w.Header().Add("Docker-Distribution-API-Version", "registry/2.0")
	w.Header().Add("WWW-Authenticate", authHeader)
	w.WriteHeader(http.StatusUnauthorized)
}

// auth manages the registry authentication. It records the user and password used and returns
// a StatusOK (regardless of the user/pass pair used). Panics if no basic auth are present.
func (m *registryAuthMock) auth(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		panic("auth endpoint called without basic auth")
	}

	scopes := r.URL.Query()["scope"]
	if len(scopes) == 0 {
		panic("auth scope not set")
	}

	slices := strings.SplitN(scopes[0], ":", 3)
	if len(slices) != 3 {
		panic("invalid scope found")
	}
	repo := slices[1]

	m.attemptedAuths = append(
		m.attemptedAuths,
		staticCreds{
			user:     user,
			pass:     pass,
			registry: fmt.Sprintf("%s/%s", r.Host, repo),
		},
	)
	w.WriteHeader(http.StatusOK)
}

// ServeHTTP dispatches handlers based on the requested URL path.
func (m *registryAuthMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v2/":
		m.ping(w, r)
	case "/v2/auth":
		m.auth(w, r)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// TestCredentialStoreFactory tests we are using the right credentials for the right registries.
// Makes sure that authentication for multiple mirrors for the same image are correctly handled.
func TestCredentialStoreFactory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	insecureTransport, err := rest.TransportFor(
		&rest.Config{
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Start by creating three different registry mocks, all of them using the same
	// underlying registryAuthMock instance.
	authMock := &registryAuthMock{}
	mirror1srv := httptest.NewTLSServer(authMock)
	defer mirror1srv.Close()

	mirror2srv := httptest.NewTLSServer(authMock)
	defer mirror2srv.Close()

	mirror3srv := httptest.NewTLSServer(authMock)
	defer mirror3srv.Close()

	for _, tt := range []struct {
		name       string
		registries []string
		auths      []staticCreds
		expauths   []staticCreds
	}{
		{
			name: "no alternate",
			auths: []staticCreds{
				{
					registry: mirror1srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror1user",
					pass:     "mirror1pass",
				},
			},
			registries: []string{
				mirror1srv.Listener.Addr().String(),
			},
		},
		{
			name: "one alternate",
			auths: []staticCreds{
				{
					registry: mirror1srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror1user",
					pass:     "mirror1pass",
				},
				{
					registry: mirror2srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror2user",
					pass:     "mirror2pass",
				},
			},
			registries: []string{
				mirror1srv.Listener.Addr().String(),
				mirror2srv.Listener.Addr().String(),
			},
		},
		{
			name: "multiple alternates",
			auths: []staticCreds{
				{
					registry: mirror1srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror1user",
					pass:     "mirror1pass",
				},
				{
					registry: mirror2srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror2user",
					pass:     "mirror2pass",
				},
				{
					registry: mirror3srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror3user",
					pass:     "mirror3pass",
				},
			},
			registries: []string{
				mirror1srv.Listener.Addr().String(),
				mirror2srv.Listener.Addr().String(),
				mirror3srv.Listener.Addr().String(),
			},
		},
		{
			name: "unused authentication",
			auths: []staticCreds{
				{
					registry: mirror1srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror1user",
					pass:     "mirror1pass",
				},
				{
					registry: mirror2srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror2user",
					pass:     "mirror2pass",
				},
				{
					registry: mirror3srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror3user",
					pass:     "mirror3pass",
				},
				{
					registry: "i.wont.be.used",
					user:     "mirror3user",
					pass:     "mirror3pass",
				},
			},
			expauths: []staticCreds{
				{
					registry: mirror1srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror1user",
					pass:     "mirror1pass",
				},
				{
					registry: mirror2srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror2user",
					pass:     "mirror2pass",
				},
				{
					registry: mirror3srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror3user",
					pass:     "mirror3pass",
				},
				{
					registry: mirror1srv.Listener.Addr().String() + "/namespace/name",
					user:     "mirror1user",
					pass:     "mirror1pass",
				},
			},
			registries: []string{
				mirror1srv.Listener.Addr().String(),
				mirror2srv.Listener.Addr().String(),
				mirror3srv.Listener.Addr().String(),
				mirror1srv.Listener.Addr().String(),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer authMock.Reset()

			refs := make([]imagereference.DockerImageReference, len(tt.registries))
			for i, registry := range tt.registries {
				refs[i] = imagereference.DockerImageReference{
					Registry:  registry,
					Namespace: "namespace",
					Name:      "name",
				}
			}

			c := NewContext(
				http.DefaultTransport, insecureTransport,
			).WithAlternateBlobSourceStrategy(
				&fakeAlternateBlobStrategy{
					FirstAlternates: refs,
				},
			).WithCredentialsFactory(
				&fakeCredentialStoreFactory{
					auths: tt.auths,
				},
			).WithCredentials(
				&staticCreds{
					user: "this-should-not-be-used",
					pass: "this-should-not-be-used",
				},
			)

			// this URL doesn't matter as we are going to use the alternates.
			urlPlaceHoder := &url.URL{Host: "quay.io"}
			repo, err := c.Repository(ctx, urlPlaceHoder, "namespace/name", false)
			if err != nil {
				t.Fatal(err)
			}

			mansvc, err := repo.Manifests(ctx)
			if err != nil {
				t.Fatal(err)
			}

			// as the registryAuthMock handles only authentication this function is
			// expected to fail, we only care about what authentication were used
			// to reach the registry therefore we can simply ignore whatever is
			// returned by this Get() call.
			mansvc.Get(ctx, "sha256:0000000000000000000000000000000000000000000000000000000000000000")

			// if not expected authentication has been set then we we expect the
			// used authentications (attemptedAuths) to be in the same order as we
			// defined them. This indicates that all mirrors have been accessed in the
			// right order and using the right authentications.
			if tt.expauths == nil {
				if !reflect.DeepEqual(tt.auths, authMock.attemptedAuths) {
					t.Errorf("expected auths attempts %+v, found %+v", tt.auths, authMock.attemptedAuths)
				}
				return
			}

			if !reflect.DeepEqual(tt.expauths, authMock.attemptedAuths) {
				t.Errorf("expected auths attempts %+v, found %+v", tt.auths, authMock.attemptedAuths)
			}
		})
	}
}

// TestCachedTransport assures that we are not reusing the same cached Transport even when
// mirroring from one repository into another inside the same registry. In a nutshell: we set
// a mirror for registry.io/original/img pointing to registry.io/mirror/img, both the original
// and the mirror repositories use different authentication data.
func TestCachedTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	insecureTransport, err := rest.TransportFor(
		&rest.Config{
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// creates a mocked registry that records authentication atttempts.
	authMock := &registryAuthMock{}
	srcsrv := httptest.NewTLSServer(authMock)
	defer srcsrv.Close()

	// this is the original image reference we are trying to pull.
	imgpath := fmt.Sprintf("%s/original/image:latest", srcsrv.Listener.Addr().String())
	originalRef, err := imagereference.Parse(imgpath)
	if err != nil {
		t.Fatal("unexpected error parsing reference: ", err)
	}

	// this is the mirror image reference.
	imgpath = fmt.Sprintf("%s/mirror/image:latest", srcsrv.Listener.Addr().String())
	mirrorRef, err := imagereference.Parse(imgpath)
	if err != nil {
		t.Fatal("unexpected error parsing reference: ", err)
	}

	// this is the order in which we expect the authentication attempts to happen,
	// first an attempt in the mirror and then an attempt in the original repo, both
	// using different user/pass pairs.
	expectedAuthAttempts := []staticCreds{
		{
			registry: srcsrv.Listener.Addr().String() + "/mirror/image",
			user:     "mirroruser",
			pass:     "mirrorpass",
		},
		{
			registry: srcsrv.Listener.Addr().String() + "/original/image",
			user:     "originaluser",
			pass:     "originalpass",
		},
	}

	impctx := NewContext(
		http.DefaultTransport, insecureTransport,
	).WithAlternateBlobSourceStrategy(
		&fakeAlternateBlobStrategy{
			FirstAlternates: []imagereference.DockerImageReference{
				mirrorRef, originalRef,
			},
		},
	).WithCredentialsFactory(
		&fakeCredentialStoreFactory{
			auths: expectedAuthAttempts,
		},
	)

	repo, err := impctx.Repository(
		ctx, originalRef.RegistryURL(), originalRef.RepositoryName(), true,
	)
	if err != nil {
		t.Fatal("unexpected error creating repository: ", err)
	}

	mansvc, err := repo.Manifests(ctx)
	if err != nil {
		t.Fatal("unexpected error creating manifest service: ", err)
	}

	// this fails because the mock does not know any about manifests, we only care for
	// the authentication attempts anyways.
	mansvc.Get(ctx, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if !reflect.DeepEqual(expectedAuthAttempts, authMock.attemptedAuths) {
		t.Errorf("expected auths attempts %+v, found %+v", expectedAuthAttempts, authMock.attemptedAuths)
	}
}

// TestReadMirrorFallback checks that the client can use all mirrors and
// doesn't send unnecessary requests.
func TestReadMirrorFallback(t *testing.T) {
	ctx := context.Background()

	insecureTransport, err := rest.TransportFor(
		&rest.Config{
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	sourceRegistry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("source registry: unexpected request to %s", r.URL.String())
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer sourceRegistry.Close()

	emptyRegistryRequests := 0
	emptyRegistry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if emptyRegistryRequests == 0 && r.Method == "GET" && r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
		} else if emptyRegistryRequests == 1 && r.Method == "GET" && r.URL.Path == "/v2/empty-mirror/image/blobs/sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
			w.WriteHeader(http.StatusNotFound)
		} else {
			t.Errorf("empty registry: unexpected request %d to %s %s", emptyRegistryRequests, r.Method, r.URL.String())
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
		emptyRegistryRequests++
	}))
	defer emptyRegistry.Close()
	defer func() {
		if emptyRegistryRequests != 2 {
			t.Errorf("empty registry: expected 2 requests, got %d", emptyRegistryRequests)
		}
	}()

	mirrorRegistryRequests := 0
	mirrorRegistry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mirrorRegistryRequests == 0 && r.Method == "GET" && r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
		} else if mirrorRegistryRequests == 1 && r.Method == "GET" && r.URL.Path == "/v2/second-mirror/image/blobs/sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
			w.Write([]byte("hello"))
		} else {
			t.Errorf("mirror registry: unexpected request %d to %s %s", mirrorRegistryRequests, r.Method, r.URL.String())
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
		mirrorRegistryRequests++
	}))
	defer mirrorRegistry.Close()
	defer func() {
		if mirrorRegistryRequests != 2 {
			t.Errorf("mirror registry: expected 2 requests, got %d", mirrorRegistryRequests)
		}
	}()

	// this is the original image reference we are trying to pull.
	imgpath := fmt.Sprintf("%s/original/image:latest", sourceRegistry.Listener.Addr().String())
	originalRef, err := imagereference.Parse(imgpath)
	if err != nil {
		t.Fatal("unexpected error parsing reference:", err)
	}

	// this is the first mirror image reference.
	imgpath = fmt.Sprintf("%s/empty-mirror/image:latest", emptyRegistry.Listener.Addr().String())
	emptyMirrorRef, err := imagereference.Parse(imgpath)
	if err != nil {
		t.Fatal("unexpected error parsing reference:", err)
	}

	// this is the second mirror image reference.
	imgpath = fmt.Sprintf("%s/second-mirror/image:latest", mirrorRegistry.Listener.Addr().String())
	secondMirrorRef, err := imagereference.Parse(imgpath)
	if err != nil {
		t.Fatal("unexpected error parsing reference:", err)
	}

	impctx := NewContext(
		http.DefaultTransport, insecureTransport,
	).WithAlternateBlobSourceStrategy(
		&fakeAlternateBlobStrategy{
			FirstAlternates: []imagereference.DockerImageReference{
				emptyMirrorRef, secondMirrorRef, originalRef,
			},
		},
	)

	repo, err := impctx.Repository(
		ctx, originalRef.RegistryURL(), originalRef.RepositoryName(), true,
	)
	if err != nil {
		t.Fatal("unexpected error creating repository:", err)
	}

	bs := repo.Blobs(ctx)

	r, err := bs.Open(ctx, "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	if err != nil {
		t.Fatal("unexpected error opening blob:", err)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal("unexpected error reading blob:", err)
	}
	if string(data) != "hello" {
		t.Fatalf("unexpected data from blob: %q", string(data))
	}
}
