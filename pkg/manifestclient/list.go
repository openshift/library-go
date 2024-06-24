package manifestclient

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// must-gather has a few different ways to store resources
// 1. cluster-scoped-resource/group/resource/<name>.yaml
// 2. cluster-scoped-resource/group/resource.yaml
// 3. namespaces/<namespace>/group/resource/<name>.yaml
// 4. namespaces/<namespace>/group/resource.yaml
// we have to choose which to prefer and we should always prefer the #2 if it's available.
// Keep in mind that to produce a cluster-scoped list of namespaced resources, you can need to navigate many namespaces.
func (mrt *manifestRoundTripper) list(requestInfo *apirequest.RequestInfo) ([]byte, error) {
	var retList *unstructured.UnstructuredList
	possibleListFiles, err := allPossibleListFileLocations(mrt.contentReader, requestInfo)
	if err != nil {
		return nil, fmt.Errorf("unable to determine list file locations: %w", err)
	}
	for _, listFile := range possibleListFiles {
		currList, err := readListFile(mrt.contentReader, listFile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// do nothing, it's possible, not guaranteed
			continue
		case err != nil:
			return nil, fmt.Errorf("unable to determine read list file %v: %w", listFile, err)
		}

		if retList == nil {
			retList = currList
			continue
		}
		for i := range currList.Items {
			retList.Items = append(retList.Items, currList.Items[i])
		}
	}
	if retList != nil {
		ret, err := serializeListObjToJSON(retList)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize: %v", err)
		}
		return []byte(ret), nil
	}

	retList = &unstructured.UnstructuredList{
		Object: map[string]interface{}{},
		Items:  nil,
	}
	individualFiles, err := allIndividualFileLocations(mrt.contentReader, requestInfo)
	if err != nil {
		return nil, fmt.Errorf("unable to determine individual file locations: %w", err)
	}
	for _, individualFile := range individualFiles {
		currInstance, err := readIndividualFile(mrt.contentReader, individualFile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// do nothing, it's possible, not guaranteed
			continue
		case err != nil:
			return nil, fmt.Errorf("unable to determine read list file %v: %w", individualFile, err)
		}

		retList.Items = append(retList.Items, *currInstance)
	}
	if len(retList.Items) > 0 {
		retList.SetKind(retList.Items[0].GetKind() + "List")
		retList.SetAPIVersion(retList.Items[0].GetAPIVersion())

		ret, err := serializeListObjToJSON(retList)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize: %v", err)
		}
		return []byte(ret), nil
	}

	return nil, fmt.Errorf("unable to read any file so we have no Kind")
}

func allIndividualFileLocations(contentReader RawReader, requestInfo *apirequest.RequestInfo) ([]string, error) {
	resourceDirectoryParts := []string{}
	if len(requestInfo.APIGroup) > 0 {
		resourceDirectoryParts = append(resourceDirectoryParts, requestInfo.APIGroup)
	} else {
		resourceDirectoryParts = append(resourceDirectoryParts, "core")
	}
	resourceDirectoryParts = append(resourceDirectoryParts, requestInfo.Resource)

	resourceDirectoriesToCheckForIndividualFiles := []string{}
	if len(requestInfo.Namespace) > 0 {
		parts := append([]string{"namespaces", requestInfo.Namespace}, resourceDirectoryParts...)
		resourceDirectoriesToCheckForIndividualFiles = append(resourceDirectoriesToCheckForIndividualFiles, filepath.Join(parts...))

	} else {
		clusterParts := append([]string{"cluster-scoped-resources"}, resourceDirectoryParts...)
		resourceDirectoriesToCheckForIndividualFiles = append(resourceDirectoriesToCheckForIndividualFiles, filepath.Join(clusterParts...))

		namespaces, err := allNamespacesWithData(contentReader)
		if err != nil {
			return nil, fmt.Errorf("unable to read namespaces")
		}
		for _, ns := range namespaces {
			nsParts := append([]string{"namespaces", ns}, resourceDirectoryParts...)
			resourceDirectoriesToCheckForIndividualFiles = append(resourceDirectoriesToCheckForIndividualFiles, filepath.Join(nsParts...))
		}
	}

	allIndividualFilePaths := []string{}
	for _, resourceDirectory := range resourceDirectoriesToCheckForIndividualFiles {
		individualFiles, err := contentReader.ReadDir(resourceDirectory)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nil, fmt.Errorf("unable to read resourceDir")
		}

		for _, curr := range individualFiles {
			allIndividualFilePaths = append(allIndividualFilePaths, filepath.Join(resourceDirectory, curr.Name()))
		}
	}

	return allIndividualFilePaths, nil
}

func allPossibleListFileLocations(contentReader RawReader, requestInfo *apirequest.RequestInfo) ([]string, error) {
	resourceListFileParts := []string{}
	if len(requestInfo.APIGroup) > 0 {
		resourceListFileParts = append(resourceListFileParts, requestInfo.APIGroup)
	} else {
		resourceListFileParts = append(resourceListFileParts, "core")
	}
	resourceListFileParts = append(resourceListFileParts, fmt.Sprintf("%s.yaml", requestInfo.Resource))

	allPossibleListFileLocations := []string{}
	if len(requestInfo.Namespace) > 0 {
		parts := append([]string{"namespaces", requestInfo.Namespace}, resourceListFileParts...)
		allPossibleListFileLocations = append(allPossibleListFileLocations, filepath.Join(parts...))

	} else {
		clusterParts := append([]string{"cluster-scoped-resources"}, resourceListFileParts...)
		allPossibleListFileLocations = append(allPossibleListFileLocations, filepath.Join(clusterParts...))

		namespaces, err := allNamespacesWithData(contentReader)
		if err != nil {
			return nil, fmt.Errorf("unable to read namespaces")
		}
		for _, ns := range namespaces {
			nsParts := append([]string{"namespaces", ns}, resourceListFileParts...)
			allPossibleListFileLocations = append(allPossibleListFileLocations, filepath.Join(nsParts...))
		}
	}

	return allPossibleListFileLocations, nil
}

func allNamespacesWithData(contentReader RawReader) ([]string, error) {
	nsDirs, err := contentReader.ReadDir("namespaces")
	if err != nil {
		return nil, fmt.Errorf("failed to read allNamespacesWithData: %w", err)
	}

	ret := []string{}
	for _, curr := range nsDirs {
		ret = append(ret, curr.Name())
	}

	return ret, nil
}
