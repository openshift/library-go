package resourceread

import (
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	admissionScheme = runtime.NewScheme()
	admissionCodecs = serializer.NewCodecFactory(admissionScheme)
)

func init() {
	if err := admissionv1.AddToScheme(admissionScheme); err != nil {
		panic(err)
	}
}

func ReadValidatingWebhookConfigurationV1OrDie(objBytes []byte) *admissionv1.ValidatingWebhookConfiguration {
	requiredObj, err := runtime.Decode(admissionCodecs.UniversalDecoder(admissionv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(err)
	}

	return requiredObj.(*admissionv1.ValidatingWebhookConfiguration)
}

func ReadMutatingWebhookConfigurationV1OrDie(objBytes []byte) *admissionv1.MutatingWebhookConfiguration {
	requiredObj, err := runtime.Decode(admissionCodecs.UniversalDecoder(admissionv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(err)
	}

	return requiredObj.(*admissionv1.MutatingWebhookConfiguration)
}
