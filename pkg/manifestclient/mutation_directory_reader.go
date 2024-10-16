package manifestclient

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"
)

func ReadMutationDirectory(mutationDirectory string) (*AllActionsTracker[FileOriginatedSerializedRequest], error) {
	return readMutationFS(os.DirFS(mutationDirectory))
}

func ReadEmbeddedMutationDirectory(inFS fs.FS) (*AllActionsTracker[FileOriginatedSerializedRequest], error) {
	return readMutationFS(inFS)
}

func readMutationFS(inFS fs.FS) (*AllActionsTracker[FileOriginatedSerializedRequest], error) {
	ret := NewAllActionsTracker[FileOriginatedSerializedRequest]()
	errs := []error{}

	for _, action := range sets.List(AllActions) {
		file, err := inFS.Open(string(action))
		if file != nil {
			file.Close()
		}
		switch {
		case os.IsNotExist(err):
			continue
		case err != nil:
			errs = append(errs, fmt.Errorf("unable to read %q : %w", action, err))
			continue
		case err == nil:
		}
		actionFS, err := fs.Sub(inFS, string(action))
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to create subFS %q: %w", action, err))
			continue
		}

		currResourceList, err := readSerializedRequestsFromActionDirectory(action, actionFS)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to read %q: %w", action, err))
		}
		ret.AddRequests(currResourceList...)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return ret, nil
}

func readSerializedRequestsFromActionDirectory(action Action, actionFS fs.FS) ([]FileOriginatedSerializedRequest, error) {
	currResourceList := []FileOriginatedSerializedRequest{}
	errs := []error{}
	err := fs.WalkDir(actionFS, ".", func(currLocation string, currFile fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
		}

		if currFile.IsDir() {
			return nil
		}
		if !strings.HasSuffix(currFile.Name(), ".yaml") && !strings.HasSuffix(currFile.Name(), ".json") {
			return nil
		}
		currResource, err := serializedRequestFromFile(action, actionFS, currLocation)
		if err != nil {
			return fmt.Errorf("error deserializing %q: %w", currLocation, err)
		}
		if currResource == nil { // not all file are body files, so those can be nil
			return nil
		}
		currResourceList = append(currResourceList, *currResource)

		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return currResourceList, nil
}

var (
	bodyRegex    = regexp.MustCompile(`(\d\d\d)-body-(.+).yaml`)
	optionsRegex = regexp.MustCompile(`(\d\d\d)-options-(.+).yaml`)
)

func serializedRequestFromFile(action Action, actionFS fs.FS, bodyFilename string) (*FileOriginatedSerializedRequest, error) {
	bodyBasename := filepath.Base(bodyFilename)
	if !bodyRegex.MatchString(bodyBasename) {
		return nil, nil
	}
	optionsBaseName := strings.Replace(bodyBasename, "body", "options", 1)
	optionsFilename := filepath.Join(filepath.Dir(bodyFilename), optionsBaseName)

	bodyContent, err := fs.ReadFile(actionFS, bodyFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", bodyFilename, err)
	}

	optionsExist := false
	optionsContent, err := fs.ReadFile(actionFS, optionsFilename)
	switch {
	case os.IsNotExist(err):
	// not required, do nothing
	case err != nil:
		return nil, fmt.Errorf("failed to read %q: %w", optionsFilename, err)
	case err == nil:
		optionsExist = true
	}

	// parse to discover bits of the serialized request
	retObj, _, jsonErr := unstructured.UnstructuredJSONScheme.Decode(bodyContent, nil, &unstructured.Unstructured{})
	if jsonErr != nil {
		// try to see if it's yaml
		jsonString, err := yaml.YAMLToJSON(bodyContent)
		if err != nil {
			return nil, fmt.Errorf("unable to decode %q as json: %w", bodyFilename, jsonErr)
		}
		retObj, _, err = unstructured.UnstructuredJSONScheme.Decode(jsonString, nil, &unstructured.Unstructured{})
		if err != nil {
			return nil, fmt.Errorf("unable to decode %q as yaml: %w", bodyFilename, err)
		}
	}

	// stepping backwards in the filename we can determine resource and group since we're using individual files, not lists
	resourceName := filepath.Base(filepath.Dir(bodyFilename))
	versionName := retObj.(*unstructured.Unstructured).GroupVersionKind().Version // not always correct, but nearly always correct. When/if we get to scale this will be interesting
	groupName := filepath.Base(filepath.Dir(filepath.Dir(bodyFilename)))
	if groupName == "core" {
		groupName = ""
	}

	metadataName := retObj.(*unstructured.Unstructured).GetName()
	if action == ActionDelete {
		metadataName = retObj.(*unstructured.Unstructured).GetAnnotations()[DeletionNameAnnotation]
	}

	ret := &FileOriginatedSerializedRequest{
		BodyFilename: bodyFilename,
		SerializedRequest: SerializedRequest{
			Action: action,
			ResourceType: schema.GroupVersionResource{
				Group:    groupName,
				Version:  versionName,
				Resource: resourceName,
			},
			KindType:  retObj.(*unstructured.Unstructured).GroupVersionKind(),
			Namespace: retObj.(*unstructured.Unstructured).GetNamespace(),
			Name:      metadataName,
			Body:      bodyContent,
		},
	}
	if optionsExist {
		ret.OptionsFilename = optionsFilename
		ret.SerializedRequest.Options = optionsContent
	}

	return ret, nil
}
