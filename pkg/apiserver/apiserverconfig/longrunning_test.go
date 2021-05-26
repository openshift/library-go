package apiserverconfig

import (
	"testing"
)

func TestIsLongRunningRequest(t *testing.T) {
	paths := []string{
		"/apis/image.openshift.io/v1/namespaces/ci-op-frj9n6jn/imagestreamimports",
	}
	for _, path := range paths {
		if !originLongRunningRequestRE.MatchString(path) {
			t.Errorf("Expected path to match: %s", path)
		}
	}
}
