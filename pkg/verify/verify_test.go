package verify

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"

	"github.com/openshift/library-go/pkg/verify/store"
	"github.com/openshift/library-go/pkg/verify/store/memory"
	"github.com/openshift/library-go/pkg/verify/store/serial"
	"github.com/openshift/library-go/pkg/verify/store/sigstore"
)

func Test_ReleaseVerifier_Verify(t *testing.T) {
	data, err := ioutil.ReadFile(filepath.Join("testdata", "keyrings", "redhat.txt"))
	if err != nil {
		t.Fatal(err)
	}
	redhatPublic, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}
	data, err = ioutil.ReadFile(filepath.Join("testdata", "keyrings", "simple.txt"))
	if err != nil {
		t.Fatal(err)
	}
	simple, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}
	data, err = ioutil.ReadFile(filepath.Join("testdata", "keyrings", "combined.txt"))
	if err != nil {
		t.Fatal(err)
	}
	combined, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	serveSignatures := http.FileServer(http.Dir(filepath.Join("testdata", "signatures")))
	sigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		serveSignatures.ServeHTTP(w, req)
	}))
	defer sigServer.Close()
	sigServerURL, _ := url.Parse(sigServer.URL)

	serveEmpty := http.FileServer(http.Dir(filepath.Join("testdata", "signatures-2")))
	emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		serveEmpty.ServeHTTP(w, req)
	}))
	defer emptyServer.Close()
	emptyServerURL, _ := url.Parse(emptyServer.URL)

	validSignatureData, err := ioutil.ReadFile(filepath.Join("testdata", "signatures", "sha256=e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7", "signature-1"))
	validSignatureStore := &memory.Store{
		Data: map[string][][]byte{
			"sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7": {
				validSignatureData,
			},
		},
	}

	tests := []struct {
		name          string
		verifiers     map[string]openpgp.EntityList
		store         store.Store
		releaseDigest string
		wantErr       bool
	}{
		{releaseDigest: "", wantErr: true},
		{releaseDigest: "!", wantErr: true},

		{
			name:          "valid signature for sha over file",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			store: &serial.Store{
				Stores: []store.Store{
					&fileStore{directory: "testdata/signatures"},
				},
			},
			verifiers: map[string]openpgp.EntityList{"redhat": redhatPublic},
		},
		{
			name:          "valid signature for sha over http",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			store:         &sigstore.Store{URI: sigServerURL, HTTPClient: sigstore.DefaultClient},
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
		},
		{
			name:          "valid signature for sha from store",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			store:         validSignatureStore,
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
		},
		{
			name:          "valid signature for sha over http with custom gpg key",
			releaseDigest: "sha256:edd9824f0404f1a139688017e7001370e2f3fbc088b94da84506653b473fe140",
			store:         &sigstore.Store{URI: sigServerURL, HTTPClient: sigstore.DefaultClient},
			verifiers:     map[string]openpgp.EntityList{"simple": simple},
		},
		{
			name:          "valid signature for sha over http with multi-key keyring",
			releaseDigest: "sha256:edd9824f0404f1a139688017e7001370e2f3fbc088b94da84506653b473fe140",
			store:         &sigstore.Store{URI: sigServerURL, HTTPClient: sigstore.DefaultClient},
			verifiers:     map[string]openpgp.EntityList{"combined": combined},
		},

		{
			name:          "store rejects if no store found",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			store:         &memory.Store{},
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			wantErr:       true,
		},
		{
			name:          "file location rejects if digest is not found",
			releaseDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			store:         &fileStore{directory: "testdata/signatures"},
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			wantErr:       true,
		},
		{
			name:          "http location rejects if digest is not found",
			releaseDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			store:         &sigstore.Store{URI: sigServerURL, HTTPClient: sigstore.DefaultClient},
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			wantErr:       true,
		},

		{
			name:          "sha contains invalid characters",
			releaseDigest: "!sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			store:         &fileStore{directory: "testdata/signatures"},
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			wantErr:       true,
		},
		{
			name:          "sha contains too many separators",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7:",
			store:         &fileStore{directory: "testdata/signatures"},
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			wantErr:       true,
		},

		{
			name:          "could not find signature in file location",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			store:         &fileStore{directory: "testdata/signatures-2"},
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			wantErr:       true,
		},
		{
			name:          "could not find signature in http location",
			releaseDigest: "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7",
			store:         &sigstore.Store{URI: emptyServerURL, HTTPClient: sigstore.DefaultClient},
			verifiers:     map[string]openpgp.EntityList{"redhat": redhatPublic},
			wantErr:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewReleaseVerifier(tt.verifiers, tt.store)
			if err := v.Verify(context.Background(), tt.releaseDigest); (err != nil) != tt.wantErr {
				t.Errorf("releaseVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_ReleaseVerifier_String(t *testing.T) {
	data, err := ioutil.ReadFile(filepath.Join("testdata", "keyrings", "redhat.txt"))
	if err != nil {
		t.Fatal(err)
	}
	redhatPublic, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		verifiers map[string]openpgp.EntityList
		store     store.Store
		want      string
	}{
		{
			name: "none",
			want: "All release image digests must have GPG signatures from <ERROR: no verifiers> - will check for signatures in containers/image format at <ERROR: no store>",
		},
		{
			name:  "HTTP store",
			store: &sigstore.Store{URI: &url.URL{Scheme: "http", Host: "localhost", Path: "test"}},
			want:  `All release image digests must have GPG signatures from <ERROR: no verifiers> - will check for signatures in containers/image format at containers/image signature store under http://localhost/test`,
		},
		{
			name:  "file store",
			store: &fileStore{directory: "absolute/path"},
			want:  "All release image digests must have GPG signatures from <ERROR: no verifiers> - will check for signatures in containers/image format at file://absolute/path",
		},
		{
			name: "Red Hat verifier",
			verifiers: map[string]openpgp.EntityList{
				"redhat": redhatPublic,
			},
			want: "All release image digests must have GPG signatures from redhat (567E347AD0044ADE55BA8A5F199E2F91FD431D51: Red Hat, Inc. (release key 2) <security@redhat.com>) - will check for signatures in containers/image format at <ERROR: no store>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewReleaseVerifier(tt.verifiers, tt.store)
			if got := fmt.Sprintf("%v", v); got != tt.want {
				t.Errorf("releaseVerifier.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ReleaseVerifier_Signatures(t *testing.T) {
	data, err := ioutil.ReadFile(filepath.Join("testdata", "keyrings", "redhat.txt"))
	if err != nil {
		t.Fatal(err)
	}
	redhatPublic, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	const signedDigest = "sha256:e3f12513a4b22a2d7c0e7c9207f52128113758d9d68c7d06b11a0ac7672966f7"

	expectedSignature, err := ioutil.ReadFile(filepath.Join("testdata", "signatures", strings.Replace(signedDigest, ":", "=", 1), "signature-1"))
	if err != nil {
		t.Fatal(err)
	}
	goodStore := &memory.Store{Data: map[string][][]byte{}}
	goodStore.Data[signedDigest] = [][]byte{expectedSignature}

	// verify we don't cache a negative result
	verifier := &releaseVerifier{
		verifiers:      map[string]openpgp.EntityList{"redhat": redhatPublic},
		store:          &memory.Store{},
		signatureCache: make(map[string][][]byte),
	}
	if err := verifier.Verify(context.Background(), signedDigest); err == nil || err.Error() != "unable to locate a valid signature for one or more sources" {
		t.Fatal(err)
	}
	if sigs := verifier.Signatures(); len(sigs) != 0 {
		t.Fatalf("%#v", sigs)
	}

	// verify we cache a valid request
	verifier = &releaseVerifier{
		verifiers:      map[string]openpgp.EntityList{"redhat": redhatPublic},
		store:          goodStore,
		signatureCache: make(map[string][][]byte),
	}
	if err := verifier.Verify(context.Background(), signedDigest); err != nil {
		t.Fatal(err)
	}
	if sigs := verifier.Signatures(); len(sigs) != 1 {
		t.Fatalf("%#v", sigs)
	}

	// verify we hit the cache instead of verifying, even after changing the store
	verifier.store = &memory.Store{}
	if err := verifier.Verify(context.Background(), signedDigest); err != nil {
		t.Fatal(err)
	}
	if sigs := verifier.Signatures(); len(sigs) != 1 {
		t.Fatalf("%#v", sigs)
	}

	// verify we maintain a maximum number of cache entries a valid request
	verifier = &releaseVerifier{
		verifiers:      map[string]openpgp.EntityList{"redhat": redhatPublic},
		store:          goodStore,
		signatureCache: make(map[string][][]byte),
	}
	for i := 0; i < maxSignatureCacheSize*2; i++ {
		verifier.signatureCache[fmt.Sprintf("test-%d", i)] = [][]byte{[]byte("blah")}
	}

	if err := verifier.Verify(context.Background(), signedDigest); err != nil {
		t.Fatal(err)
	}
	if sigs := verifier.Signatures(); len(sigs) != maxSignatureCacheSize || !reflect.DeepEqual(sigs[signedDigest], [][]byte{expectedSignature}) {
		t.Fatalf("%d %#v", len(sigs), sigs)
	}
}
