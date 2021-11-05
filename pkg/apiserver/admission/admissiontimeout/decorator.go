package admissiontimeout

import (
	"time"

	"k8s.io/apiserver/pkg/admission"
)

const defaultAdmissionTimeout = 13 * time.Second

// WithTimeout decorates admission plugin with timeout
func WithTimeout(admissionPlugin admission.Interface, name string) admission.Interface {
	return pluginHandlerWithTimeout{
		name:             name,
		admissionPlugin:  admissionPlugin,
		admissionTimeout: defaultAdmissionTimeout,
	}
}
