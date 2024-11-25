package manifestclient

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/yaml"

	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

func (mrt *manifestRoundTripper) getGroupResourceDiscovery(requestInfo *apirequest.RequestInfo) ([]byte, error) {
	switch {
	case requestInfo.Path == "/api":
		return mrt.getAggregatedDiscoveryForURL("aggregated-discovery-api.yaml", requestInfo.Path)
	case requestInfo.Path == "/apis":
		return mrt.getAggregatedDiscoveryForURL("aggregated-discovery-apis.yaml", requestInfo.Path)
	default:
		// TODO can probably do better
		return nil, fmt.Errorf("unsupported discovery path: %q", requestInfo.Path)
	}
}

func (mrt *manifestRoundTripper) getAggregatedDiscoveryForURL(filename, url string) ([]byte, error) {
	discoveryBytes, err := fs.ReadFile(mrt.sourceFS, filename)
	if errors.Is(err, fs.ErrNotExist) {
		discoveryBytes, err = fs.ReadFile(defaultDiscovery, filepath.Join("default-discovery", filename))
	}
	if err != nil {
		return nil, fmt.Errorf("error reading discovery: %w", err)
	}

	apiMap := map[string]interface{}{}
	if err := yaml.Unmarshal(discoveryBytes, &apiMap); err != nil {
		return nil, fmt.Errorf("discovery %q unmarshal failed: %w", url, err)
	}
	apiJSON, err := json.Marshal(apiMap)
	if err != nil {
		return nil, fmt.Errorf("discovery %q marshal failed: %w", url, err)
	}

	return apiJSON, err
}
