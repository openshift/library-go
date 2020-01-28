package resourceread

import (
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	scheme = runtime.NewScheme()
	codes  = serializer.NewCodecFactory(scheme)
)

func init() {
	if err := batchv1beta1.AddToScheme(scheme); err != nil {
		panic(err)
	}
}

func ReadCronJobV1beta1OrDie(objBytes []byte) *batchv1beta1.CronJob {
	requiredObj, err := runtime.Decode(coreCodecs.UniversalDecoder(batchv1beta1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(err)
	}
	return requiredObj.(*batchv1beta1.CronJob)
}
