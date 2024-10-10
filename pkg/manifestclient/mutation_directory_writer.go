package manifestclient

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func WriteMutationDirectory[T SerializedRequestish](mutationDirectory string, requests ...T) error {
	errs := []error{}

	for _, request := range requests {
		bodyFilename, optionsFilename := request.SuggestedFilenames()
		bodyPath := filepath.Join(mutationDirectory, bodyFilename)

		parentDir := filepath.Dir(bodyPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			errs = append(errs, fmt.Errorf("unable to create parentDir %q: %w", parentDir, err))
			continue
		}
		if err := os.WriteFile(bodyPath, request.GetSerializedRequest().Body, 0644); err != nil {
			errs = append(errs, fmt.Errorf("unable to write body %v: %w", request, err))
		}
		if len(request.GetSerializedRequest().Options) > 0 {
			optionsPath := filepath.Join(mutationDirectory, optionsFilename)
			if err := os.WriteFile(optionsPath, request.GetSerializedRequest().Options, 0644); err != nil {
				errs = append(errs, fmt.Errorf("unable to write options %v: %w", request, err))
			}
		}

	}

	return errors.Join(errs...)
}
