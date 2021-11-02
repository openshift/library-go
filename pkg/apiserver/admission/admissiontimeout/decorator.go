package admissiontimeout

import (
	"k8s.io/apiserver/pkg/admission"
)

func WithTimeout(admissionPlugin admission.Interface, name string) admission.Interface {
	return pluginHandlerWithTimeout{
		name:            name,
		admissionPlugin: admissionPlugin,
	}
}
