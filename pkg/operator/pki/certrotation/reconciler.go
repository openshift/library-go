package certrotation

import (
	"context"
	stdcrypto "crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certutil "k8s.io/client-go/util/cert"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
	"github.com/openshift/library-go/pkg/operator/pki/certrotation/internal/engine"
	"github.com/openshift/library-go/pkg/operator/pki/certrotation/internal/store"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	"github.com/openshift/library-go/pkg/pki"
)

// readYourWritesWindow is how long after a write the reconciler distrusts
// its lister cache for that artifact and reads live instead.
const readYourWritesWindow = 30 * time.Second

// writeRecord remembers a write for the read-your-writes guard.
type writeRecord struct {
	resourceVersion string
	writtenAt       time.Time
}

// Reconciler performs level-triggered reconcile passes over one Rotation:
// signer, then bundle, then each target. It has no background goroutines and
// is usable with or without a controller (CNO embeds it in a
// controller-runtime loop; oc and CKAO RunOnce call it once; the v2
// controller wraps it).
type Reconciler struct {
	rotation Rotation
	opts     Options
	store    *store.Store
	writes   map[string]writeRecord
	// pendingAction carries the action recorded by the step methods of the
	// current pass; Reconcile collects it after each step.
	pendingAction *Action
}

// collectAction moves the step's pending action, if any, into the result.
func (r *Reconciler) collectAction(result *Result) {
	if r.pendingAction != nil {
		result.Actions = append(result.Actions, *r.pendingAction)
		r.pendingAction = nil
	}
}

// NewReconciler validates the Rotation and Options and returns a reconciler.
// Construction errors are configuration bugs, not runtime conditions.
func NewReconciler(rotation Rotation, opts Options) (*Reconciler, error) {
	if err := rotation.Validate(); err != nil {
		return nil, err
	}
	if err := opts.validate(false); err != nil {
		return nil, err
	}
	if err := checkLegacyPeerCertConstraint(rotation, opts.PKI.mode); err != nil {
		return nil, err
	}
	return &Reconciler{
		rotation: rotation,
		opts:     opts,
		store:    store.New(opts.KubeClient, opts.Informers),
		writes:   map[string]writeRecord{},
	}, nil
}

// Result reports what a pass did and what it failed on.
type Result struct {
	// Actions lists the writes the pass performed.
	Actions []Action
	// TargetErrors maps each target name to its error, nil on success.
	// Signer and bundle failures are attributed to every target.
	TargetErrors map[string]error
	// NextCheck is the earliest instant at which a decision can change.
	// The controller uses it for AddAfter.
	NextCheck time.Time
}

// Op identifies the kind of write performed on an artifact.
type Op string

const (
	OpCreated          Op = "created"
	OpRegenerated      Op = "regenerated"
	OpMetadataRepaired Op = "metadata-repaired"
)

// Action records one write.
type Action struct {
	Artifact ArtifactRef
	Op       Op
	Reason   string
}

// Reconcile performs one pass. The returned error is an errors.Join of the
// per-artifact errors; Result carries the same information with attribution.
func (r *Reconciler) Reconcile(ctx context.Context) (Result, error) {
	now := r.now()

	result := Result{
		TargetErrors: make(map[string]error, len(r.rotation.Targets)),
	}
	for i := range r.rotation.Targets {
		result.TargetErrors[r.rotation.Targets[i].Name] = nil
	}
	fail := func(err error) (Result, error) {
		for name := range result.TargetErrors {
			result.TargetErrors[name] = err
		}
		return result, err
	}

	// Resolve PKI configuration once per pass. A provider error is
	// ErrPKIConfig and aborts the pass; there is never a silent fallback.
	keyGens, pkiErr := r.resolveKeyGens()
	if pkiErr != nil {
		return fail(&ArtifactError{
			Artifact: r.signerRef(),
			Phase:    PhaseClassify,
			Err:      fmt.Errorf("%w: %v", ErrPKIConfig, pkiErr),
		})
	}

	// Signer step.
	signerCA, signerCert, signerErr := r.reconcileSigner(ctx, now, keyGens.signer)
	r.collectAction(&result)
	if signerErr != nil {
		return fail(signerErr)
	}

	// Bundle step.
	bundlePEM, bundleCerts, bundleErr := r.reconcileBundle(ctx, now, signerCert)
	r.collectAction(&result)
	if bundleErr != nil {
		return fail(bundleErr)
	}

	// Target steps, independent per target.
	nextCheck := signerNextCheck(signerCert, r.rotation.Signer.Refresh, now)
	for i := range r.rotation.Targets {
		target := r.rotation.Targets[i]
		action, targetNext, err := r.reconcileTarget(ctx, target, now, signerCA, signerCert, bundlePEM, bundleCerts, keyGens.targets[target.Name])
		if err != nil {
			result.TargetErrors[target.Name] = err
			continue
		}
		if action != nil {
			result.Actions = append(result.Actions, *action)
		}
		if targetNext.Before(nextCheck) {
			nextCheck = targetNext
		}
	}
	result.NextCheck = nextCheck

	var allErrs []error
	for name, err := range result.TargetErrors {
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("target %s: %w", name, err))
		}
	}
	return result, errors.Join(allErrs...)
}

func (r *Reconciler) now() time.Time {
	if r.opts.Clock != nil {
		return r.opts.Clock.Now()
	}
	return time.Now()
}

// keyGenerations carries the resolved key generator per artifact; nil
// generators mean legacy issuance.
type keyGenerations struct {
	signer  crypto.KeyPairGenerator
	targets map[string]crypto.KeyPairGenerator
}

// resolveKeyGens resolves the PKI configuration once and derives a key
// generator per artifact. Legacy PKI resolves nothing and never fails.
func (r *Reconciler) resolveKeyGens() (keyGenerations, error) {
	result := keyGenerations{targets: map[string]crypto.KeyPairGenerator{}}
	if r.opts.PKI.mode != pkiModeConfigurable {
		return result, nil
	}
	spec, err := r.opts.PKI.provider.Config()
	if err != nil {
		return result, err
	}
	signerCfg, err := pki.ResolveCertificateConfig(spec.Certificates, pki.CertificateTypeCA, r.rotation.Signer.CertificateName)
	if err != nil {
		return result, err
	}
	result.signer = signerCfg.Key
	for i := range r.rotation.Targets {
		target := r.rotation.Targets[i]
		cfg, err := pki.ResolveCertificateConfig(spec.Certificates, target.Cert.certificateType(), target.CertificateName)
		if err != nil {
			return result, err
		}
		result.targets[target.Name] = cfg.Key
	}
	return result, nil
}

// keyGenAlgorithm reports the algorithm string of a resolved generator for
// key-drift comparison, or "" when it cannot be determined.
func keyGenAlgorithm(gen crypto.KeyPairGenerator) string {
	switch g := gen.(type) {
	case crypto.RSAKeyPairGenerator:
		return "RSA"
	case crypto.ECDSAKeyPairGenerator:
		return "ECDSA"
	default:
		_ = g
		return ""
	}
}

func (r *Reconciler) signerRef() ArtifactRef {
	return ArtifactRef{Kind: ArtifactKindSigner, Location: r.rotation.Signer.Location}
}

func targetRef(target Target) ArtifactRef {
	return ArtifactRef{Kind: ArtifactKindTarget, Location: target.Location}
}

func (r *Reconciler) bundleRef() ArtifactRef {
	return ArtifactRef{Kind: ArtifactKindBundle, Location: r.rotation.Bundle.Location}
}

// getSecret reads a secret through the read-your-writes guard: if this
// reconciler wrote the artifact recently and the lister disagrees about the
// resource version, read live instead.
func (r *Reconciler) getSecret(ctx context.Context, location Location) (*corev1.Secret, error) {
	secret, err := r.store.GetSecret(ctx, location.Namespace, location.Name)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, nil
	}
	if record, exists := r.writes[location.String()]; exists {
		stale := time.Since(record.writtenAt) < readYourWritesWindow && secret.ResourceVersion != record.resourceVersion
		if stale {
			return r.store.GetSecretLive(ctx, location.Namespace, location.Name)
		}
	}
	return secret, nil
}

// parsedArtifact is the parsed content of a TLS secret, in the shape the
// engine classifies. Parse failures are classification inputs, not errors:
// malformed data is StateInvalid, and an unrecognized key algorithm is left
// to the binary that can judge it.
type parsedArtifact struct {
	exists             bool
	cert               *x509.Certificate
	key                stdcrypto.PrivateKey
	keyParseErr        error
	notAfterAnnotation string
}

func parseArtifact(secret *corev1.Secret) parsedArtifact {
	parsed := parsedArtifact{exists: secret != nil}
	if secret == nil {
		return parsed
	}
	parsed.notAfterAnnotation = secret.Annotations[contract.CertificateNotAfterAnnotation]

	certBytes := secret.Data[contract.SecretCertKey]
	if len(certBytes) > 0 {
		certs, err := certutil.ParseCertsPEM(certBytes)
		if err == nil && len(certs) > 0 {
			parsed.cert = certs[0]
		}
	}
	keyBytes := secret.Data[contract.SecretKeyKey]
	if len(keyBytes) > 0 {
		key, err := crypto.ParsePrivateKeyPEM(keyBytes)
		if err != nil {
			parsed.keyParseErr = err
		} else {
			parsed.key = key
		}
	}
	return parsed
}

// writeSecret persists a secret: Create when there is no existing object,
// Update with the existing resourceVersion otherwise. Conflicts are typed
// ErrConflict and never swallowed. The persisted object is recorded for the
// read-your-writes guard and returned.
func (r *Reconciler) writeSecret(ctx context.Context, ref ArtifactRef, desired *corev1.Secret, existing *corev1.Secret) (*corev1.Secret, *ArtifactError) {
	if existing == nil {
		persisted, err := r.store.CreateSecret(ctx, desired)
		if persisted == nil {
			persisted = desired
		}
		resourcehelper.ReportCreateEvent(r.opts.Recorder, persisted, err)
		if err != nil {
			return nil, r.writeError(ref, err)
		}
		r.recordWrite(ref.Location, persisted.ResourceVersion)
		return persisted, nil
	}
	desired.ResourceVersion = existing.ResourceVersion
	persisted, err := r.store.UpdateSecret(ctx, desired)
	if persisted == nil {
		persisted = desired
	}
	resourcehelper.ReportUpdateEvent(r.opts.Recorder, persisted, err)
	if err != nil {
		return nil, r.writeError(ref, err)
	}
	r.recordWrite(ref.Location, persisted.ResourceVersion)
	return persisted, nil
}

func (r *Reconciler) writeError(ref ArtifactRef, err error) *ArtifactError {
	if apierrors.IsConflict(err) {
		return &ArtifactError{Artifact: ref, Phase: PhaseWrite, Err: fmt.Errorf("%w: %v", ErrConflict, err)}
	}
	return &ArtifactError{Artifact: ref, Phase: PhaseWrite, Err: err}
}

func (r *Reconciler) recordWrite(location Location, resourceVersion string) {
	r.writes[location.String()] = writeRecord{resourceVersion: resourceVersion, writtenAt: r.now()}
}

// reconcileSigner ensures the signer secret and returns the parsed CA of the
// persisted object.
func (r *Reconciler) reconcileSigner(ctx context.Context, now time.Time, keyGen crypto.KeyPairGenerator) (*crypto.CA, *x509.Certificate, *ArtifactError) {
	ref := r.signerRef()
	existing, err := r.getSecret(ctx, r.rotation.Signer.Location)
	if err != nil {
		return nil, nil, &ArtifactError{Artifact: ref, Phase: PhaseRead, Err: err}
	}
	parsed := parseArtifact(existing)
	state, reason := engine.ClassifySigner(engine.SignerInputs{
		Exists:               parsed.exists,
		ParsedCert:           parsed.cert,
		ParsedKey:            parsed.key,
		KeyParseErr:          parsed.keyParseErr,
		NotAfterAnnotation:   parsed.notAfterAnnotation,
		Refresh:              r.rotation.Signer.Refresh,
		ResolvedKeyAlgorithm: keyGenAlgorithm(keyGen),
	}, now)
	action := engine.Decide(state, r.opts.Role)

	switch action {
	case engine.ActionCreate, engine.ActionRegenerate:
		r.opts.Recorder.Eventf("SignerUpdateRequired", "signer %s requires a new signing cert/key pair: %s", ref.Location, reason)
		issued, err := issueSigner(r.rotation.Signer.Namespace, r.rotation.Signer.Name, r.rotation.Signer.Validity, keyGen, now)
		if err != nil {
			return nil, nil, &ArtifactError{Artifact: ref, Phase: PhaseIssue, Err: err}
		}
		desired := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: r.rotation.Signer.Namespace,
				Name:      r.rotation.Signer.Name,
			},
			Type: corev1.SecretTypeTLS,
		}
		certBytes, keyBytes, err := issued.GetPEMBytes()
		if err != nil {
			return nil, nil, &ArtifactError{Artifact: ref, Phase: PhaseIssue, Err: err}
		}
		desired.Data = map[string][]byte{
			contract.SecretCertKey: certBytes,
			contract.SecretKeyKey:  keyBytes,
		}
		setComputedAnnotations(&desired.ObjectMeta, issued, r.rotation.Signer.Refresh)
		r.applyMetadata(&desired.ObjectMeta, r.rotation.Signer.Metadata, contract.CertificateTypeSigner, r.rotation.Owner)
		persisted, writeErr := r.writeSecret(ctx, ref, desired, existing)
		if writeErr != nil {
			return nil, nil, writeErr
		}
		op := OpRegenerated
		if existing == nil {
			op = OpCreated
		}
		r.pendingAction = &Action{Artifact: ref, Op: op, Reason: reason}
		return r.parsePersistedCA(persisted, ref)

	case engine.ActionRepairMeta:
		repaired := existing.DeepCopy()
		modified := r.applyMetadata(&repaired.ObjectMeta, r.rotation.Signer.Metadata, contract.CertificateTypeSigner, r.rotation.Owner)
		if ensureSecretType(repaired) {
			modified = true
		}
		if !modified {
			return r.parsePersistedCA(existing, ref)
		}
		persisted, writeErr := r.writeSecret(ctx, ref, repaired, existing)
		if writeErr != nil {
			return nil, nil, writeErr
		}
		r.pendingAction = &Action{Artifact: ref, Op: OpMetadataRepaired, Reason: reason}
		return r.parsePersistedCA(persisted, ref)

	default:
		if r.opts.Role == RoleWriter && existing != nil {
			repaired := existing.DeepCopy()
			modified := r.applyMetadata(&repaired.ObjectMeta, r.rotation.Signer.Metadata, contract.CertificateTypeSigner, r.rotation.Owner)
			if ensureSecretType(repaired) {
				modified = true
			}
			if modified {
				persisted, writeErr := r.writeSecret(ctx, ref, repaired, existing)
				if writeErr != nil {
					return nil, nil, writeErr
				}
				r.pendingAction = &Action{Artifact: ref, Op: OpMetadataRepaired, Reason: "metadata drift"}
				return r.parsePersistedCA(persisted, ref)
			}
		}
		return r.parsePersistedCA(existing, ref)
	}
}

// parsePersistedCA parses the CA from a persisted signer secret. A failure
// is an invariant error and aborts the pass.
func (r *Reconciler) parsePersistedCA(secret *corev1.Secret, ref ArtifactRef) (*crypto.CA, *x509.Certificate, *ArtifactError) {
	if secret == nil {
		return nil, nil, &ArtifactError{Artifact: ref, Phase: PhaseVerify, Err: fmt.Errorf("%w: signer secret vanished after write", ErrInvariant)}
	}
	certBytes := secret.Data[contract.SecretCertKey]
	keyBytes := secret.Data[contract.SecretKeyKey]
	if len(certBytes) == 0 || len(keyBytes) == 0 {
		return nil, nil, &ArtifactError{Artifact: ref, Phase: PhaseVerify, Err: fmt.Errorf("%w: signer secret missing tls.crt or tls.key", ErrInvariant)}
	}
	ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
	if err != nil {
		return nil, nil, &ArtifactError{Artifact: ref, Phase: PhaseVerify, Err: fmt.Errorf("%w: %v", ErrInvariant, err)}
	}
	return ca, ca.Config.Certs[0], nil
}

// reconcileBundle ensures the bundle configmap and verifies its invariants
// on the persisted object. Both roles fix bundle content (idempotent); only
// the writer repairs bundle metadata.
func (r *Reconciler) reconcileBundle(ctx context.Context, now time.Time, signerCert *x509.Certificate) (string, []*x509.Certificate, *ArtifactError) {
	ref := r.bundleRef()
	existing, err := r.store.GetConfigMap(ctx, r.rotation.Bundle.Namespace, r.rotation.Bundle.Name)
	if err != nil {
		return "", nil, &ArtifactError{Artifact: ref, Phase: PhaseRead, Err: err}
	}

	var existingCerts []*x509.Certificate
	if existing != nil && len(existing.Data[contract.CABundleConfigMapKey]) > 0 {
		existingCerts, err = engine.ParseCABundle(existing.Data[contract.CABundleConfigMapKey])
		if err != nil {
			// An unparseable existing bundle is treated as empty content:
			// the desired bundle replaces it.
			existingCerts = nil
		}
	}
	desiredPEM, desiredCerts := engine.DesiredBundle(existingCerts, signerCert)

	contentDiffers := existing == nil || existing.Data[contract.CABundleConfigMapKey] != desiredPEM
	if contentDiffers {
		r.opts.Recorder.Eventf("CABundleUpdateRequired", "CA bundle configmap %s requires an update", ref.Location)
		desired := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: r.rotation.Bundle.Namespace,
				Name:      r.rotation.Bundle.Name,
			},
			Data: map[string]string{contract.CABundleConfigMapKey: desiredPEM},
		}
		r.applyMetadata(&desired.ObjectMeta, r.rotation.Bundle.Metadata, contract.CertificateTypeCABundle, r.rotation.Owner)
		var persisted *corev1.ConfigMap
		if existing == nil {
			persisted, err = r.store.CreateConfigMap(ctx, desired)
			if persisted == nil {
				persisted = desired
			}
			resourcehelper.ReportCreateEvent(r.opts.Recorder, persisted, err)
		} else {
			desired.ResourceVersion = existing.ResourceVersion
			persisted, err = r.store.UpdateConfigMap(ctx, desired)
			if persisted == nil {
				persisted = desired
			}
			resourcehelper.ReportUpdateEvent(r.opts.Recorder, persisted, err)
		}
		if err != nil {
			return "", nil, r.writeError(ref, err)
		}
		r.recordWrite(ref.Location, persisted.ResourceVersion)
		r.pendingAction = &Action{Artifact: ref, Op: OpRegenerated, Reason: "bundle content updated"}
		// Verify the invariants on the object the API server persisted, not
		// on what we intended to write: a conflicting writer or a faulty
		// reactor could have stored anything.
		if err := engine.BundleContainsSigner(persisted.Data[contract.CABundleConfigMapKey], signerCert); err != nil {
			return "", nil, &ArtifactError{Artifact: ref, Phase: PhaseVerify, Err: fmt.Errorf("%w: %v", ErrInvariant, err)}
		}
		return persisted.Data[contract.CABundleConfigMapKey], desiredCerts, nil
	}

	// Writer repairs bundle metadata on an otherwise current bundle.
	if r.opts.Role == RoleWriter && existing != nil {
		repaired := existing.DeepCopy()
		if r.applyMetadata(&repaired.ObjectMeta, r.rotation.Bundle.Metadata, contract.CertificateTypeCABundle, r.rotation.Owner) {
			repaired.ResourceVersion = existing.ResourceVersion
			persisted, err := r.store.UpdateConfigMap(ctx, repaired)
			resourcehelper.ReportUpdateEvent(r.opts.Recorder, persisted, err)
			if err != nil {
				return "", nil, r.writeError(ref, err)
			}
			r.recordWrite(ref.Location, persisted.ResourceVersion)
			r.pendingAction = &Action{Artifact: ref, Op: OpMetadataRepaired, Reason: "bundle metadata repaired"}
		}
	}

	// Verify the invariants on the persisted bundle: non-empty, parses, and
	// contains the current signer. A failure is ErrInvariant and targets are
	// never evaluated against it.
	if existing != nil {
		if err := engine.BundleContainsSigner(existing.Data[contract.CABundleConfigMapKey], signerCert); err != nil {
			return "", nil, &ArtifactError{Artifact: ref, Phase: PhaseVerify, Err: fmt.Errorf("%w: %v", ErrInvariant, err)}
		}
	}
	return desiredPEM, desiredCerts, nil
}

// signerNextCheck computes the earliest instant the signer's decision can
// change: the nearest of the 80% boundary, the refresh boundary, and expiry.
func signerNextCheck(signerCert *x509.Certificate, refresh time.Duration, now time.Time) time.Time {
	if signerCert == nil {
		return now.Add(refresh)
	}
	validity := signerCert.NotAfter.Sub(signerCert.NotBefore)
	candidates := []time.Time{
		signerCert.NotBefore.Add(refresh),
		signerCert.NotAfter.Add(-validity / 5),
		signerCert.NotAfter,
	}
	next := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.Before(next) {
			next = candidate
		}
	}
	if next.Before(now) {
		return now
	}
	return next
}

// applyMetadata applies the caller metadata, the managed-certificate-type
// label, and (for the writer) the owner reference to an artifact's object
// meta. It reports whether anything changed. It never removes values.
func (r *Reconciler) applyMetadata(meta *metav1.ObjectMeta, metadata Metadata, certificateType string, owner *metav1.OwnerReference) bool {
	modified := metadata.Apply(meta)
	if meta.Labels == nil {
		meta.Labels = map[string]string{}
	}
	if meta.Labels[contract.ManagedCertificateTypeLabelName] != certificateType {
		meta.Labels[contract.ManagedCertificateTypeLabelName] = certificateType
		modified = true
	}
	if r.opts.Role == RoleWriter && owner != nil {
		if ensureOwnerReference(meta, owner) {
			modified = true
		}
	}
	return modified
}

// setComputedAnnotations writes the rotation-computed annotations derived
// from the issued certificate: issuer, not-before, not-after and
// refresh-period. These are write-only output for external readers.
func setComputedAnnotations(meta *metav1.ObjectMeta, issued *crypto.TLSCertificateConfig, refresh time.Duration) {
	if meta.Annotations == nil {
		meta.Annotations = map[string]string{}
	}
	meta.Annotations[contract.CertificateIssuer] = issued.Certs[0].Issuer.CommonName
	meta.Annotations[contract.CertificateNotBeforeAnnotation] = contract.FormatValidityTime(issued.Certs[0].NotBefore)
	meta.Annotations[contract.CertificateNotAfterAnnotation] = contract.FormatValidityTime(issued.Certs[0].NotAfter)
	meta.Annotations[contract.CertificateRefreshPeriodAnnotation] = contract.FormatRefreshPeriod(refresh)
}

// ensureOwnerReference adds the owner to the owner references if missing.
func ensureOwnerReference(meta *metav1.ObjectMeta, owner *metav1.OwnerReference) bool {
	if slices.Contains(meta.OwnerReferences, *owner) {
		return false
	}
	meta.OwnerReferences = append(meta.OwnerReferences, *owner)
	return true
}

// ensureSecretType normalizes a pre-4.7 Opaque secret to kubernetes.io/tls,
// wiping data if the TLS keys are missing, exactly as v1's
// ensureSecretTLSTypeSet did.
func ensureSecretType(secret *corev1.Secret) bool {
	if len(secret.ResourceVersion) == 0 {
		return false
	}
	if secret.Type != corev1.SecretTypeTLS {
		secret.Type = corev1.SecretTypeTLS
		if _, certExists := secret.Data[contract.SecretCertKey]; !certExists {
			secret.Data = map[string][]byte{}
		}
		if _, keyExists := secret.Data[contract.SecretKeyKey]; !keyExists {
			secret.Data = map[string][]byte{}
		}
		return true
	}
	return false
}
