package manifestclient

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/yaml"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

func (mrt *manifestRoundTripper) getGroupResourceDiscovery(requestInfo *apirequest.RequestInfo) ([]byte, error) {
	switch {
	case requestInfo.Path == "/api":
		ret, err := mrt.getAggregatedDiscoveryForURL("aggregated-discovery-api.yaml", requestInfo.Path)
		if errors.Is(err, fs.ErrNotExist) {
			return mrt.getLegacyGroupResourceDiscovery(requestInfo)
		}
		return ret, err
	case requestInfo.Path == "/apis":
		ret, err := mrt.getAggregatedDiscoveryForURL("aggregated-discovery-apis.yaml", requestInfo.Path)
		if errors.Is(err, fs.ErrNotExist) {
			return mrt.getLegacyGroupResourceDiscovery(requestInfo)
		}
		return ret, err
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

func (mrt *manifestRoundTripper) getLegacyGroupResourceDiscovery(requestInfo *apirequest.RequestInfo) ([]byte, error) {
	if len(requestInfo.Path) == 0 {
		return nil, fmt.Errorf("path required for group resource discovery")
	}

	apiResourceList := &metav1.APIResourceList{}

	group, version, err := splitGroupVersionFromRequestPath(requestInfo.Path)
	if err != nil {
		return nil, fmt.Errorf("unable to split group/version from path: %w", err)
	}

	apiResourceList.GroupVersion = fmt.Sprintf("%s/%s", group, version)
	if group == "core" {
		apiResourceList.GroupVersion = version
	}

	// Map of resource name to APIResource.
	apiResources := map[string]metav1.APIResource{}

	clusterGroupPath := filepath.Join("cluster-scoped-resources", group)
	clusterGroupDirEntries, err := fs.ReadDir(mrt.sourceFS, clusterGroupPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("unable to read directory: %w", err)
	}

	apiResourcesForClusterScope, err := getAPIResourcesFromNamespaceDirEntries(clusterGroupDirEntries, mrt.sourceFS, group, version, clusterGroupPath, false /* cluster-scoped */)
	if err != nil {
		return nil, fmt.Errorf("unable to get resources from cluster-scoped directory: %w", err)
	}
	for resourceName, apiResource := range apiResourcesForClusterScope {
		apiResources[resourceName] = apiResource
	}

	namespaceDirEntries, err := fs.ReadDir(mrt.sourceFS, "namespaces")
	if err != nil {
		return nil, fmt.Errorf("unable to read directory: %w", err)
	}
	for _, namespaceDirEntry := range namespaceDirEntries {
		if !namespaceDirEntry.IsDir() {
			continue
		}

		namespaceGroupPath := filepath.Join("namespaces", namespaceDirEntry.Name(), group)
		namespaceGroupDirEntries, err := fs.ReadDir(mrt.sourceFS, namespaceGroupPath)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("unable to read directory: %w", err)
		} else if errors.Is(err, fs.ErrNotExist) {
			// No resources for this namespace.
			continue
		}

		apiResourcesForNamespace, err := getAPIResourcesFromNamespaceDirEntries(namespaceGroupDirEntries, mrt.sourceFS, group, version, namespaceGroupPath, true /* namespaced */)
		if err != nil {
			return nil, fmt.Errorf("unable to get resources from namespace directory: %w", err)
		}

		for resourceName, apiResource := range apiResourcesForNamespace {
			apiResources[resourceName] = apiResource
		}

		// Namespaces are special: each namespace is stored in its own file within the namespace directory
		namespacePath := filepath.Join("namespaces", namespaceDirEntry.Name(), namespaceDirEntry.Name()+".yaml")
		if namespaceObj, err := readIndividualFile(mrt.sourceFS, namespacePath); err == nil {
			// It's currently not guaranteed that the file is always present
			apiResources["namespaces"] = metav1.APIResource{
				Name:       "namespaces",
				Kind:       namespaceObj.GetKind(),
				Group:      namespaceObj.GroupVersionKind().Group,
				Version:    namespaceObj.GroupVersionKind().Version,
				Namespaced: false,
				Verbs:      []string{"get", "list", "watch"},
			}
		}
	}

	for _, apiResource := range apiResources {
		apiResourceList.APIResources = append(apiResourceList.APIResources, apiResource)
	}

	ret, err := serializeAPIResourceListToJSON(apiResourceList)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize group resource discovery: %v", err)
	}
	return []byte(ret), nil
}

func splitGroupVersionFromRequestPath(path string) (string, string, error) {
	if path == "/api/v1" {
		return "core", "v1", nil
	}

	parts := strings.Split(path, "/")
	if len(parts) != 4 {
		return "", "", fmt.Errorf("invalid path: %s", path)
	}

	return parts[2], parts[3], nil
}

func getResourceDirAPIServerListEntry(sourceFS fs.FS, groupPath, resourceName, group, version string, namespaced bool) (*metav1.APIResource, error) {
	resourceDirEntries, err := fs.ReadDir(sourceFS, filepath.Join(groupPath, resourceName))
	if err != nil {
		return nil, fmt.Errorf("unable to read directory: %w", err)
	}
	for _, fileEntry := range resourceDirEntries {
		if !strings.HasSuffix(fileEntry.Name(), ".yaml") {
			// There shouldn't be anything that hits this, but ignore it if there is.
			continue
		}

		individualObj, individualErr := readIndividualFile(sourceFS, filepath.Join(groupPath, resourceName, fileEntry.Name()))
		if individualErr != nil {
			return nil, fmt.Errorf("unable to read file: %w", individualErr)
		}

		groupVersion := fmt.Sprintf("%s/%s", group, version)
		if group == "core" {
			group = ""
			groupVersion = version
		}

		if individualObj.GetAPIVersion() != groupVersion {
			continue
		}

		// No point checking further, all files should produce the same APIResource.
		return &metav1.APIResource{
			Name:       resourceName,
			Kind:       individualObj.GetKind(),
			Group:      group,
			Version:    version,
			Namespaced: namespaced,
			Verbs:      []string{"get", "list", "watch"},
		}, nil
	}

	return nil, nil
}

func getAPIResourcesFromNamespaceDirEntries(dirEntries []fs.DirEntry, sourceFS fs.FS, group, version string, basePath string, namespaced bool) (map[string]metav1.APIResource, error) {
	apiResources := map[string]metav1.APIResource{}
	for _, dirEntry := range dirEntries {
		// Directories are named after the resource and contain individual resources.
		if dirEntry.IsDir() {
			apiResource, err := getResourceDirAPIServerListEntry(sourceFS, basePath, dirEntry.Name(), group, version, namespaced)
			if err != nil {
				return nil, fmt.Errorf("unable to get resource from directory: %w", err)
			}
			if apiResource != nil {
				apiResources[dirEntry.Name()] = *apiResource
			}
		}

		if !strings.HasSuffix(dirEntry.Name(), ".yaml") {
			// There shouldn't be anything that hits this, but ignore it if there is.
			continue
		}

		resourceName := strings.TrimSuffix(dirEntry.Name(), ".yaml")
		if _, ok := apiResources[resourceName]; ok {
			// We already have this resource.
			continue
		}

		// Files are named after the resource and contain a list of resources.
		listObj, err := readListFile(sourceFS, filepath.Join(basePath, dirEntry.Name()))
		if err != nil {
			return nil, fmt.Errorf("unable to read list file: %w", err)
		}

		for _, obj := range listObj.Items {
			if obj.GetAPIVersion() != fmt.Sprintf("%s/%s", group, version) {
				continue
			}

			apiResources[resourceName] = metav1.APIResource{
				Name:       resourceName,
				Kind:       obj.GetKind(),
				Group:      group,
				Version:    version,
				Namespaced: namespaced,
				Verbs:      []string{"get", "list", "watch"},
			}

			// Once we find a resource in the expected group/version, we can break.
			// Anything else would produce the same APIResource.
			break
		}
	}

	return apiResources, nil
}
