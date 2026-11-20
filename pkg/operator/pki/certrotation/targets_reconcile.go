package certrotation

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
	"github.com/openshift/library-go/pkg/operator/pki/certrotation/internal/engine"
)

// reconcileTarget ensures one target secret. Errors are per-target and do
// not abort the pass. It returns the action performed (if any) and the
// target's next decision boundary.
func (r *Reconciler) reconcileTarget(ctx context.Context, target Target, now time.Time, signerCA *crypto.CA, signerCert *x509.Certificate, bundlePEM string, bundleCerts []*x509.Certificate, keyGen crypto.KeyPairGenerator) (*Action, time.Time, error) {
	ref := targetRef(target)
	existing, err := r.getSecret(ctx, target.Location)
	if err != nil {
		return nil, now.Add(target.Refresh), &ArtifactError{Artifact: ref, Phase: PhaseRead, Err: err}
	}
	parsed := parseArtifact(existing)

	hostnames, hostnamesErr := r.targetHostnames(target)
	if hostnamesErr != nil {
		return nil, now.Add(target.Refresh), &ArtifactError{Artifact: ref, Phase: PhaseClassify, Err: hostnamesErr}
	}

	state, reason := engine.ClassifyTarget(engine.TargetInputs{
		Exists:               parsed.exists,
		ParsedCert:           parsed.cert,
		ParsedKey:            parsed.key,
		KeyParseErr:          parsed.keyParseErr,
		NotAfterAnnotation:   parsed.notAfterAnnotation,
		Refresh:              target.Refresh,
		DesiredHostnames:     hostnames,
		SignerNotBefore:      signerCert.NotBefore,
		BundleCerts:          bundleCerts,
		ResolvedKeyAlgorithm: keyGenAlgorithm(keyGen),
	}, now)
	action := engine.Decide(state, r.opts.Role)

	nextCheck := targetNextCheck(parsed.cert, target.Refresh, signerCert, now)

	switch action {
	case engine.ActionCreate, engine.ActionRegenerate:
		r.opts.Recorder.Eventf("TargetUpdateRequired", "target %s requires a new cert/key pair: %s", ref.Location, reason)
		issued, err := issueTarget(target, hostnames, signerCA, keyGen, now)
		if err != nil {
			return nil, nextCheck, &ArtifactError{Artifact: ref, Phase: PhaseIssue, Err: err}
		}
		certBytes, keyBytes, err := issued.GetPEMBytes()
		if err != nil {
			return nil, nextCheck, &ArtifactError{Artifact: ref, Phase: PhaseIssue, Err: err}
		}
		// Regenerate on top of the existing object so foreign metadata,
		// labels, owner references and extra data keys survive, exactly as
		// v1's DeepCopy-based regeneration did. Both roles preserve what is
		// there; only the writer adds new metadata.
		desired := regenerateOver(existing, target.Location)
		desired.Type = corev1.SecretTypeTLS
		desired.Data = map[string][]byte{
			contract.SecretCertKey: certBytes,
			contract.SecretKeyKey:  keyBytes,
		}
		setComputedAnnotations(&desired.ObjectMeta, issued, target.Refresh)
		if err := r.setHostnameAnnotations(&desired.ObjectMeta, target, issued); err != nil {
			return nil, nextCheck, &ArtifactError{Artifact: ref, Phase: PhaseIssue, Err: err}
		}
		r.applyMetadata(&desired.ObjectMeta, target.Metadata, contract.CertificateTypeTarget, r.rotation.Owner)
		persisted, writeErr := r.writeSecret(ctx, ref, desired, existing)
		if writeErr != nil {
			return nil, nextCheck, writeErr
		}
		// Recompute the next boundary from the issued cert.
		refreshed := parseArtifact(persisted)
		nextCheck = targetNextCheck(refreshed.cert, target.Refresh, signerCert, now)
		op := OpRegenerated
		if existing == nil {
			op = OpCreated
		}
		return &Action{Artifact: ref, Op: op, Reason: reason}, nextCheck, nil

	default:
		if r.opts.Role == RoleWriter && existing != nil {
			repaired := existing.DeepCopy()
			modified := r.applyMetadata(&repaired.ObjectMeta, target.Metadata, contract.CertificateTypeTarget, r.rotation.Owner)
			if ensureSecretType(repaired) {
				modified = true
			}
			if modified {
				persisted, writeErr := r.writeSecret(ctx, ref, repaired, existing)
				if writeErr != nil {
					return nil, nextCheck, writeErr
				}
				_ = persisted
				return &Action{Artifact: ref, Op: OpMetadataRepaired, Reason: "metadata drift"}, nextCheck, nil
			}
		}
		return nil, nextCheck, nil
	}
}

// targetHostnames resolves the desired hostname set for serving and peer
// targets. An empty set is ErrInputNotReady for that target only; other
// targets proceed. Client and intermediate-signer targets have no hostnames.
func (r *Reconciler) targetHostnames(target Target) ([]string, error) {
	switch cert := target.Cert.(type) {
	case ServingCert:
		hostnames := cert.Hostnames.Hostnames()
		if len(hostnames) == 0 {
			return nil, fmt.Errorf("%w: no hostnames set for target %s", ErrInputNotReady, target.Name)
		}
		return hostnames, nil
	case PeerCert:
		hostnames := cert.Hostnames.Hostnames()
		if len(hostnames) == 0 {
			return nil, fmt.Errorf("%w: no hostnames set for target %s", ErrInputNotReady, target.Name)
		}
		return hostnames, nil
	default:
		return nil, nil
	}
}

// setHostnameAnnotations writes the hostnames annotation for serving and
// peer targets, as v1's ServingRotation.SetAnnotations did: the sorted,
// comma-joined set of the issued certificate's DNS names and IP addresses.
func (r *Reconciler) setHostnameAnnotations(meta *metav1.ObjectMeta, target Target, issued *crypto.TLSCertificateConfig) error {
	switch target.Cert.(type) {
	case ServingCert, PeerCert:
		if meta.Annotations == nil {
			meta.Annotations = map[string]string{}
		}
		meta.Annotations[contract.CertificateHostnames] = contract.FormatHostnames(hostnamesOf(issued))
	}
	return nil
}

func hostnamesOf(config *crypto.TLSCertificateConfig) []string {
	hostnames := make([]string, 0, len(config.Certs[0].DNSNames)+len(config.Certs[0].IPAddresses))
	for _, ip := range config.Certs[0].IPAddresses {
		hostnames = append(hostnames, ip.String())
	}
	for _, dnsName := range config.Certs[0].DNSNames {
		hostnames = append(hostnames, dnsName)
	}
	return hostnames
}

// targetNextCheck computes the earliest instant the target's decision can
// change, including the signer trust-propagation gate.
func targetNextCheck(cert *x509.Certificate, refresh time.Duration, signerCert *x509.Certificate, now time.Time) time.Time {
	if cert == nil {
		return now.Add(refresh)
	}
	validity := cert.NotAfter.Sub(cert.NotBefore)
	candidates := []time.Time{
		cert.NotBefore.Add(refresh),
		cert.NotAfter.Add(-validity / 5),
		cert.NotAfter,
		// The signer-age gate: a Due-by-refresh decision can flip once the
		// signer is Refresh/10 into its life (the target's refresh).
		signerCert.NotBefore.Add(refresh / 10),
	}
	return earliestFuture(candidates, now)
}

// earliestFuture returns the earliest candidate after now; when every
// candidate has passed it returns now plus the smallest unit of headroom so
// the controller still schedules a resync rather than collapsing to the
// past.
func earliestFuture(candidates []time.Time, now time.Time) time.Time {
	next := time.Time{}
	for _, candidate := range candidates {
		if !candidate.After(now) {
			continue
		}
		if next.IsZero() || candidate.Before(next) {
			next = candidate
		}
	}
	if next.IsZero() {
		return now
	}
	return next
}
