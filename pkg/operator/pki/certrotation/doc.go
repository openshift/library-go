// Package certrotation is the v2 certificate rotation package. It manages
// the lifecycle of internally-generated TLS artifacts: a self-signed signing
// CA stored in a Secret, a CA trust bundle stored in a ConfigMap, and target
// certificates (serving, client, peer, or intermediate signer) signed by that
// CA and stored in Secrets.
//
// It is a parallel, opt-in replacement for pkg/operator/certrotation. The v1
// package is frozen; consumers migrate by building the same Rotation config
// and switching the constructor. The on-cluster contract (annotation and
// label keys and values, data keys, Secret type, subject CN formats) is
// byte-identical, so v1 and v2 can run against the same artifacts during a
// feature-gated transition, including mixed writer/healer versions during
// upgrades.
//
// The design in brief:
//
//   - Config is plain data. Rotation groups one signer, its bundle, and all
//     targets the signer signs, so one reconcile loop owns each signer.
//   - The controller owns all plumbing: pass a kubernetes.Interface and an
//     InformerSource and it derives its own informers, listers and clients.
//   - Rotation decisions are made by a pure engine, classify then decide,
//     over the parsed resource contents. Annotations are write-only output
//     for external readers (oc tooling, support, origin tests); the only
//     annotation read is the force-regeneration sentinel, an inbound command
//     from oc adm certificates.
//   - Role is required and explicit: RoleWriter owns the full lifecycle;
//     RoleHealer restores only unusable artifacts (missing, expired, invalid)
//     and never fights the writer. This replaces v1's RefreshOnlyWhenExpired.
//   - PKI is required and explicit: LegacyPKI reproduces v1's pre-ConfigurablePKI
//     generation exactly; ConfigurablePKI resolves keys through the PKI API
//     with no silent fallback.
//   - Every write is Create or Update with a resourceVersion precondition;
//     conflicts surface as typed ErrConflict and are never swallowed.
//
// The package is marked EXPERIMENTAL until the ConfigurablePKI feature gate
// carrying it reaches Default.
package certrotation
