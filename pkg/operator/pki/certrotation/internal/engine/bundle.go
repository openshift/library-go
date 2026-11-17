package engine

import (
	"bytes"
	"crypto/x509"
	"reflect"
	"sort"

	certutil "k8s.io/client-go/util/cert"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
)

// ParseCABundle parses the PEM content of a CA bundle configmap. An empty or
// unparseable bundle is an error; callers treat that as an invariant failure
// and never evaluate targets against it.
func ParseCABundle(bundlePEM string) ([]*x509.Certificate, error) {
	if len(bundlePEM) == 0 {
		return nil, errEmptyBundle
	}
	return certutil.ParseCertsPEM([]byte(bundlePEM))
}

// DesiredBundle computes the desired CA bundle content: the current signer
// prepended to the existing bundle, expired CAs pruned, duplicates removed,
// and the result byte-sorted stably. This mirrors v1's
// manageCABundleConfigMap exactly, including the sort that keeps bundle
// content stable across syncs so consumers do not see revision churn.
//
// The returned string is the PEM-encoded bundle for the ca-bundle.crt data
// key. The returned certificates are the parsed content of that PEM.
func DesiredBundle(existing []*x509.Certificate, currentSigner *x509.Certificate) (string, []*x509.Certificate) {
	certificates := append([]*x509.Certificate{currentSigner}, existing...)
	certificates = crypto.FilterExpiredCerts(certificates...)

	finalCertificates := []*x509.Certificate{}
	// Check for duplicates. n^2, but super simple (kept from v1).
	for i := range certificates {
		found := false
		for j := range finalCertificates {
			if reflect.DeepEqual(certificates[i].Raw, finalCertificates[j].Raw) {
				found = true
				break
			}
		}
		if !found {
			finalCertificates = append(finalCertificates, certificates[i])
		}
	}

	// Sorting ensures we don't continuously swap the certificates in the
	// bundle, which might cause revision rollouts (kept from v1).
	sort.SliceStable(finalCertificates, func(i, j int) bool {
		return bytes.Compare(finalCertificates[i].Raw, finalCertificates[j].Raw) < 0
	})
	bundleBytes, err := crypto.EncodeCertificates(finalCertificates...)
	if err != nil {
		// EncodeCertificates only fails on nil certificates, which cannot
		// occur here because every element was parsed.
		return "", nil
	}
	return string(bundleBytes), finalCertificates
}

// BundleContainsSigner verifies the persisted bundle invariants: it is
// non-empty, parses, and contains the current signer (raw-byte equal). This
// check after every bundle write makes the empty-bundle target regeneration
// class of bugs (OCPBUGS-60045, OCPBUGS-65525) structurally impossible: no
// target is ever evaluated against a bundle that failed verification.
func BundleContainsSigner(bundlePEM string, currentSigner *x509.Certificate) error {
	certificates, err := ParseCABundle(bundlePEM)
	if err != nil {
		return err
	}
	for _, certificate := range certificates {
		if bytes.Equal(certificate.Raw, currentSigner.Raw) {
			return nil
		}
	}
	return errMissingCurrentSigner
}

// errEmptyBundle and errMissingCurrentSigner are wrapped by callers into
// ErrInvariant artifact errors.
var (
	errEmptyBundle          = &BundleError{msg: "CA bundle is empty"}
	errMissingCurrentSigner = &BundleError{msg: "CA bundle does not contain the current signer"}
)

// BundleError reports a CA bundle invariant violation.
type BundleError struct {
	msg string
}

func (e *BundleError) Error() string { return e.msg }

// BundlePEMKey is the data key of the bundle payload, re-exported from the
// contract for engine-internal use.
const BundlePEMKey = contract.CABundleConfigMapKey
