package resourceread

import (
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	policyScheme = runtime.NewScheme()
	policyCodecs = serializer.NewCodecFactory(policyScheme)
)

func init() {
	if err := policyv1.AddToScheme(coreScheme); err != nil {
		panic(err)
	}
}

func ReadPDBV1OrDie(objBytes []byte) *policyv1.PodDisruptionBudget {
	requiredObj, err := runtime.Decode(coreCodecs.UniversalDecoder(policyv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(err)
	}
	return requiredObj.(*policyv1.PodDisruptionBudget)
}