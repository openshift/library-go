package auth

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAPIVersions(t *testing.T) {
	const header = "Docker-Distribution-API-Version"

	tests := []struct {
		name             string
		headerName       string
		headerValue      string
		expectedVersions []string
	}{{
		name:             "HeaderPresentExactName",
		headerName:       header,
		headerValue:      "registry/2.0",
		expectedVersions: []string{"registry/2.0"},
	}, {
		name:             "HeaderPresentLowerCaseName",
		headerName:       strings.ToLower(header),
		headerValue:      "registry/2.0",
		expectedVersions: []string{"registry/2.0"},
	}, {
		name:             "HeaderPresentMultipleValues",
		headerName:       header,
		headerValue:      "registry/2.0 registry/3.0",
		expectedVersions: []string{"registry/2.0", "registry/3.0"},
	}, {
		name:             "HeaderMissing",
		headerName:       header,
		headerValue:      "",
		expectedVersions: nil,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := http.Response{
				Header: make(map[string][]string),
			}
			if test.headerValue != "" {
				resp.Header.Set(test.headerName, test.headerValue)
			}

			versions := APIVersions(&resp, header)
			if !cmp.Equal(test.expectedVersions, versions) {
				t.Error("Unexpected versions slice:\n", cmp.Diff(test.expectedVersions, versions))
			}
		})
	}
}
