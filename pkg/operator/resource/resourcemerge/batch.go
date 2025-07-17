package resourcemerge

import (
	operatorsv1 "github.com/openshift/api/operator/v1"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func ExpectedJobGeneration(required *batchv1.Job, previousGenerations []operatorsv1.GenerationStatus) int64 {
	generation := GenerationFor(previousGenerations, schema.GroupResource{Group: "batch", Resource: "jobs"}, required.Namespace, required.Name)
	if generation != nil {
		return generation.LastGeneration
	}
	return -1
}
