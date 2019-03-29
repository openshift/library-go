package metrics

import (
	"fmt"
	"strings"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

// LabelAsManagedConfigMap add label indicating the given config map contains certificates
// that are managed and monitored.
func LabelAsManagedConfigMap(config *v1.ConfigMap, certificateType CertificateType) {
	if config.Labels == nil {
		config.Labels = map[string]string{}
	}
	config.Labels[ManagedCertificateTypeLabelName] = string(certificateType)
}

// LabelAsManagedConfigMap add label indicating the given secret contains certificates
// that are managed and monitored.
func LabelAsManagedSecret(secret *v1.Secret, certificateType CertificateType) {
	if secret.Labels == nil {
		secret.Labels = map[string]string{}
	}
	secret.Labels[ManagedCertificateTypeLabelName] = string(certificateType)
}

// GetCertificateTypeFromObject returns the CertificateType based on the annotations of the object.
func GetCertificateTypeFromObject(obj runtime.Object) CertificateType {
	accesor, err := meta.Accessor(obj)
	if err != nil {
		return CertificateTypeUnknown
	}
	labels := accesor.GetLabels()
	if labels == nil {
		return CertificateTypeUnknown
	}
	switch CertificateType(labels[ManagedCertificateTypeLabelName]) {
	case CertificateTypeCABundle:
		return CertificateTypeCABundle
	case CertificateTypeSigner:
		return CertificateTypeSigner
	case CertificateTypeTarget:
		return CertificateTypeTarget
	default:
		return CertificateTypeUnknown
	}
}

// getCertificateManagedLabelSelector returns a label selector that can be used in list or watch to filter
// only secrets or configmaps that are labeled as managed.
func getCertificateManagedLabelSelector() labels.Selector {
	selector, err := labels.Parse(fmt.Sprintf("%s in (%s)", ManagedCertificateTypeLabelName, strings.Join([]string{
		string(CertificateTypeCABundle),
		string(CertificateTypeTarget),
		string(CertificateTypeSigner),
	}, ",")))
	if err != nil {
		panic(err)
	}
	return selector
}
