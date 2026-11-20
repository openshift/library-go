package contract

import (
	"github.com/google/go-cmp/cmp"
	"github.com/openshift/api/annotations"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

// Metadata is the caller-supplied, non-computed metadata of a TLS artifact.
// The rotation code writes it to the artifact annotations so that artifact
// ownership and purpose can be discovered without reading the certificate.
//
// Computed rotation state (not-before, not-after, issuer, hostnames,
// refresh-period) is not part of Metadata; the rotation code owns those
// annotations and derives their values from the issued certificate.
//
// Metadata mirrors the caller-supplied fields of certrotation's
// AdditionalAnnotations and replaces it for new code.
type Metadata struct {
	// JiraComponent annotates TLS artifacts so that the owning component can
	// be easily found.
	JiraComponent string

	// Description is a human-readable one sentence description of the
	// certificate purpose.
	Description string

	// TestName is an e2e test name which verifies that the TLS artifact is
	// created and used correctly.
	TestName string

	// AutoRegenerateAfterOfflineExpiry contains a link to the PR which adds
	// this annotation on the TLS artifact, verifying that the artifact is
	// correctly regenerated after it has expired.
	AutoRegenerateAfterOfflineExpiry string
}

// Apply writes the non-empty fields of m into the annotations of meta and
// reports whether anything changed. Fields left empty in m are never written
// and existing values are never removed, so Apply is safe to call on
// artifacts shared with writers that supply a different Metadata.
func (m Metadata) Apply(meta *metav1.ObjectMeta) bool {
	modified := false
	if meta.Annotations == nil {
		meta.Annotations = make(map[string]string)
	}
	if len(m.JiraComponent) > 0 && meta.Annotations[annotations.OpenShiftComponent] != m.JiraComponent {
		diff := cmp.Diff(meta.Annotations[annotations.OpenShiftComponent], m.JiraComponent)
		klog.V(2).Infof("Updating %q annotation for %s/%s, diff: %s", annotations.OpenShiftComponent, meta.Namespace, meta.Name, diff)
		meta.Annotations[annotations.OpenShiftComponent] = m.JiraComponent
		modified = true
	}
	if len(m.Description) > 0 && meta.Annotations[annotations.OpenShiftDescription] != m.Description {
		diff := cmp.Diff(meta.Annotations[annotations.OpenShiftDescription], m.Description)
		klog.V(2).Infof("Updating %q annotation for %s/%s, diff: %s", annotations.OpenShiftDescription, meta.Namespace, meta.Name, diff)
		meta.Annotations[annotations.OpenShiftDescription] = m.Description
		modified = true
	}
	if len(m.TestName) > 0 && meta.Annotations[CertificateTestNameAnnotation] != m.TestName {
		diff := cmp.Diff(meta.Annotations[CertificateTestNameAnnotation], m.TestName)
		klog.V(2).Infof("Updating %q annotation for %s/%s, diff: %s", CertificateTestNameAnnotation, meta.Namespace, meta.Name, diff)
		meta.Annotations[CertificateTestNameAnnotation] = m.TestName
		modified = true
	}
	if len(m.AutoRegenerateAfterOfflineExpiry) > 0 && meta.Annotations[CertificateAutoRegenerateAfterOfflineExpiryAnnotation] != m.AutoRegenerateAfterOfflineExpiry {
		diff := cmp.Diff(meta.Annotations[CertificateAutoRegenerateAfterOfflineExpiryAnnotation], m.AutoRegenerateAfterOfflineExpiry)
		klog.V(2).Infof("Updating %q annotation for %s/%s, diff: %s", CertificateAutoRegenerateAfterOfflineExpiryAnnotation, meta.Namespace, meta.Name, diff)
		meta.Annotations[CertificateAutoRegenerateAfterOfflineExpiryAnnotation] = m.AutoRegenerateAfterOfflineExpiry
		modified = true
	}
	return modified
}
