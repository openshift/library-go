package certrotation

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
)

// Location identifies a namespaced object holding one artifact of a Rotation.
type Location struct {
	Namespace string
	Name      string
}

func (l Location) String() string {
	return fmt.Sprintf("%s/%s", l.Namespace, l.Name)
}

// Metadata is the caller-supplied, non-computed metadata written to the
// Rotation's artifacts. It is field-compatible with v1's caller-supplied
// AdditionalAnnotations fields.
type Metadata = contract.Metadata

// Rotation is one signer, its trust bundle, and the targets the signer
// signs. Grouping all targets of a signer into one Rotation means one
// reconcile loop owns the signer; in v1, up to four controllers each
// independently "ensured" the same signer secret.
//
// Targets may be empty, in which case the Rotation maintains only the signer
// and its bundle.
type Rotation struct {
	Signer  SignerConfig
	Bundle  BundleConfig
	Targets []Target

	// Owner, if set, is added (never replaced) to every artifact by the
	// writer. Healers never write owner references.
	Owner *metav1.OwnerReference
}

// SignerConfig configures the self-signed signing CA of the Rotation.
type SignerConfig struct {
	Location

	// CertificateName is the certificate's PKI well-known name (prefixed
	// qualified name) used for configuration resolution under
	// ConfigurablePKI. Optional: without a name, resolution falls back to the
	// per-category defaults.
	CertificateName string

	// Validity is the lifetime of newly-issued signer certificates. Must be
	// greater than zero.
	Validity time.Duration

	// Refresh is the interval at which the signer is rotated when nothing
	// else forces it. Must be greater than zero. The 80%-of-validity renewal
	// bound also applies, as in v1.
	Refresh time.Duration

	Metadata Metadata
}

// BundleConfig configures the CA trust bundle ConfigMap of the Rotation. The
// bundle always contains the current signer, pruned of expired CAs, deduped
// and byte-sorted, exactly as v1's manageCABundleConfigMap produced.
type BundleConfig struct {
	Location

	Metadata Metadata
}

// Target configures one certificate signed by the Rotation's signer.
type Target struct {
	// Name identifies the target in status conditions
	// (CertRotation_<Name>_Degraded) and in Result.TargetErrors. It must be
	// unique within the Rotation. For continuity with v1, use the v1
	// controller name for the same artifact.
	Name string

	Location

	// CertificateName is the target's PKI well-known name used for
	// configuration resolution under ConfigurablePKI. Optional.
	CertificateName string

	// Validity is the lifetime of newly-issued target certificates, clamped
	// to the signer's remaining lifetime at issue time. Must be greater than
	// zero.
	Validity time.Duration

	// Refresh is the interval at which the target is rotated when nothing
	// else forces it. Must be greater than zero.
	Refresh time.Duration

	Metadata Metadata

	// Cert describes what kind of certificate to issue. Required.
	Cert TargetCert
}

// Validate checks the Rotation for construction errors. Advisory concerns
// (refresh longer than validity, target validity beyond the signer's
// lifetime) are warnings in v1 semantics and are not rejected here.
func (r Rotation) Validate() error {
	if err := r.Signer.validate(); err != nil {
		return err
	}
	if err := r.Bundle.Location.validate("bundle"); err != nil {
		return err
	}
	seenNames := make(map[string]struct{}, len(r.Targets))
	// Secrets and ConfigMaps are distinct objects even at the same
	// namespace/name, so secret-location uniqueness is checked among the
	// signer and targets only; the bundle is a configmap.
	seenSecrets := map[Location]struct{}{
		r.Signer.Location: {},
	}
	for i := range r.Targets {
		if err := r.Targets[i].validate(); err != nil {
			return err
		}
		if _, exists := seenNames[r.Targets[i].Name]; exists {
			return fmt.Errorf("duplicate target name %q", r.Targets[i].Name)
		}
		seenNames[r.Targets[i].Name] = struct{}{}
		if _, exists := seenSecrets[r.Targets[i].Location]; exists {
			return fmt.Errorf("duplicate secret location %s", r.Targets[i].Location)
		}
		seenSecrets[r.Targets[i].Location] = struct{}{}
	}
	return nil
}

func (s SignerConfig) validate() error {
	if err := s.Location.validate("signer"); err != nil {
		return err
	}
	if s.Validity <= 0 {
		return fmt.Errorf("signer %s: validity must be greater than zero", s.Location)
	}
	if s.Refresh <= 0 {
		return fmt.Errorf("signer %s: refresh must be greater than zero", s.Location)
	}
	return nil
}

func (t Target) validate() error {
	if t.Name == "" {
		return fmt.Errorf("target %s: name is required", t.Location)
	}
	if err := t.Location.validate("target " + t.Name); err != nil {
		return err
	}
	if t.Validity <= 0 {
		return fmt.Errorf("target %s: validity must be greater than zero", t.Name)
	}
	if t.Refresh <= 0 {
		return fmt.Errorf("target %s: refresh must be greater than zero", t.Name)
	}
	if t.Cert == nil {
		return fmt.Errorf("target %s: Cert is required", t.Name)
	}
	return t.Cert.validate()
}

func (l Location) validate(noun string) error {
	if l.Namespace == "" {
		return fmt.Errorf("%s %s: namespace is required", noun, l.Name)
	}
	if l.Name == "" {
		return fmt.Errorf("%s in namespace %s: name is required", noun, l.Namespace)
	}
	return nil
}
