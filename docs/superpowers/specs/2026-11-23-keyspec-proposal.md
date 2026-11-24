# Proposal: `crypto.KeySpec` — separate key parameters from key generation

**Status:** Draft
**Date:** 2026-11-23
**Related:** PR #2535 (`configurable-pki`), PR #2584 (`keygenerator-rework`), PR #2550 (`KeyPairGenerator.Matches`)

## Summary

`crypto.KeyPairGenerator` has absorbed three responsibilities, only one of
which is generation. Since the concrete generator structs were unexported (to
enforce the RSA floor), there is no nameable, inspectable value that represents
"the key I want." This proposal introduces `crypto.KeySpec`: an inert,
comparable data type describing key parameters, from which validated generators
are produced.

## Background

Types examined:

- `pkg/crypto/keygen.go` — `KeyAlgorithm`, `ECDSACurve`, the unexported
  `rsaKeyPairGenerator` / `ecdsaKeyPairGenerator`, and their validating
  constructors.
- `pkg/pki/resolve.go` — `ResolvedCertificateConfig{Key crypto.KeyPairGenerator}`
  and `ResolveCertificateConfig`.

Relevant history:

- **Upstream master** exports `RSAKeyPairGenerator{Bits}` and
  `ECDSAKeyPairGenerator{Curve}`. Those struct literals *were* the spec.
- **#2550** (benluddy) added `Matches(pub)` to the interface. Its stated
  purpose: "inspect existing keys and decide whether their parameters are
  consistent with a certain configuration: for cert/key rotation controllers,
  testing, and PKI inventory."
- **`configurable-pki` (fdfcaffd9)** unexported the generator structs behind
  `NewRSAKeyPairGenerator` / `NewECDSAKeyPairGenerator` so the 2048-bit RSA
  floor cannot be bypassed by a struct literal.
- **#2584** adds `SecurityLevel()` to the `KeyPairGenerator` interface.

## Problem

`KeyPairGenerator` now carries three roles:

| Role | Method | Depends on |
|---|---|---|
| Produce a key | `GenerateKeyPair()` | generation |
| Test an existing key against the config | `Matches(pub)` | parameters only |
| Rank strength | `securityBits` (configurable-pki) / `SecurityLevel()` (#2584) | parameters only |

Roles two and three are questions about *parameters*, attached to a *factory*.
That worked on upstream master because the exported struct was both. Once the
structs were unexported — correctly, for the floor — the only nameable spec
disappeared. Consequences:

1. **Strength comparison is a closed-world type switch.** `securityBits`
   (`pkg/crypto/strength.go:41`) switches on the unexported structs and errors
   on anything else.

2. **Resolved generators cannot be compared.** `ResolveCertificateConfig` wraps
   its result in `selfCheckingKeyPairGenerator` (`pkg/pki/resolve.go:42-46`), so
   `crypto.StrongerKeyPairGenerator(cfgA.Key, cfgB.Key)` on two resolved configs
   fails with "cannot determine security strength of key generator
   pki.selfCheckingKeyPairGenerator". It only works today because
   `resolvePeerKeyConfig` compares before the wrap. Any external consumer (for
   example cross-signing, CNTRLPLANE-4684) would hit this.

3. **Resolved configuration is opaque.** Logging, PKI inventory, and test
   failure messages cannot ask "what algorithm and size did this resolve to?" —
   only `Matches` yes/no. Cert inventory (`certgraphapi.PublicKeyAlgorithm`) is
   precisely the reporting use case `Matches` cannot serve.

4. **`crypto.KeyAlgorithm` is dead code.** It has zero references outside its
   own declaration (`pkg/crypto/keygen.go:15`), here and on upstream master —
   a sign that the type it was meant to belong to is missing.

5. **#2584 widens an exported interface.** Adding `SecurityLevel()` to
   `KeyPairGenerator` breaks every out-of-tree implementer (including test
   fakes in consumer repos), and its tie-break still type-asserts
   `crypto.ECDSAKeyPairGenerator`.

6. **Post-quantum algorithms multiply the cost.** ML-DSA under the current
   design means another unexported generator, another arm in `strength.go`,
   and another arm in `pki.KeyPairGeneratorFromAPI`.

7. **`Matches` has no production caller yet.** Outside tests, its only caller
   is the self-check wrapper; certrotation does not regenerate on key-config
   change (`needNewTargetCertKeyPair` is time-based only). The API is being
   shaped ahead of its primary consumer, which makes now the cheapest time to
   get it right.

## Proposal

Split key *parameters* (inert data) from key *generation* (validated behavior):

```go
// pkg/crypto

// KeySpec describes the parameters of a key pair. It is plain data: comparable
// with ==, printable, and not validated on construction.
type KeySpec struct {
    Algorithm  KeyAlgorithm
    RSABits    int        // set only when Algorithm == RSAKeyAlgorithm
    ECDSACurve ECDSACurve // set only when Algorithm == ECDSAKeyAlgorithm
}

// Validate reports whether s describes a supported key: algorithm set, RSA at
// or above MinRSAKeySize, a known curve, and no fields set for another
// algorithm.
func (s KeySpec) Validate() error

// KeyPairGenerator validates s and returns a generator for it. It is the only
// way to obtain a built-in generator.
func (s KeySpec) KeyPairGenerator() (KeyPairGenerator, error)

// SecurityLevel returns the strength of keys matching s.
func (s KeySpec) SecurityLevel() SecurityLevel

// String returns a human-readable form, e.g. "ECDSA P-384" or "RSA 3072".
func (s KeySpec) String() string

// KeySpecFromPublicKey returns the spec an existing public key satisfies.
func KeySpecFromPublicKey(pub crypto.PublicKey) (KeySpec, error)
```

### What this resolves

- **The floor guarantee is preserved.** A `KeySpec` literal that violates the
  floor is harmless data; the only path to a generator still validates. The
  rationale for unexporting the generator structs remains intact.
- **`Matches` gets a single codepath.** It reduces to
  `KeySpecFromPublicKey(pub) == s` with a descriptive error — honoring #2550's
  "symmetric methods sharing one codepath" goal, while also letting inventory
  *report* a key's spec instead of only testing it.
- **Strength becomes field arithmetic.** Choosing the stronger of two specs is
  a comparison of values: no type switch, ECDSA tie-break is
  `s.Algorithm == ECDSAKeyAlgorithm`, and the wrapper problem disappears.
- **The interface does not grow.** `KeyPairGenerator` need not gain
  `SecurityLevel()`; out-of-tree implementers are unaffected.
- **Resolution becomes pure data.** `ResolvedCertificateConfig.Key` and
  `ResolvedKeyConfig.Key` become `KeySpec`; certrotation calls
  `.KeyPairGenerator()` at the point of generation. `pki.KeyPairGeneratorFromAPI`
  becomes a field mapping, `pki.KeySpecFromAPI`.
- **`KeyAlgorithm` earns its keep** as the spec's discriminator.
- **ML-DSA is additive:** one more `Algorithm` value and a parameter-set field.

## Design decisions to make

### Flat struct vs. sealed interface

- **Flat struct (recommended).** Mirrors the API's discriminated
  `PKIKeyConfig`, supports `==`, and uses `KeyAlgorithm`. Cost: invalid
  combinations are representable, so `Validate` must reject them.
- **Sealed interface** (`RSAKeySpec{Bits}`, `ECDSAKeySpec{Curve}`). Invalid
  combinations are unrepresentable, but this is upstream master's exported
  generator structs renamed, and loses `==` across algorithms.

### Whether `Matches` stays on `KeyPairGenerator`

`Matches` is upstream API (#2550). The low-risk path keeps it on the
interface, with built-in generators delegating to their spec, while `KeySpec`
becomes the primary path for new code.

### Where it lands

This is a crypto-layer change, so it fits #2584 (master-based, already
reworking `pkg/crypto`) better than #2535, which is in review. It also
reconciles a divergence between the two branches: #2584 keeps the generator
structs exported; `configurable-pki` unexports them. With `KeySpec`, the *spec*
is exported and the *generators* stay unexported.

Changing `Resolved*Config.Key` from `KeyPairGenerator` to `KeySpec` is a Tech
Preview break in the same category as the already-accepted
`ResolveCertificateConfig` signature change. The CKAO and service-ca proof PRs
should be checked for direct use of `cfg.Key`.

### Naming

`KeySpec` reads well within `pkg/crypto`. `KeyParams` is the alternative if
echoing the API's `*Spec` naming convention is a concern.

## Next step

Prototype `KeySpec` and `KeySpecFromPublicKey` on the `keygenerator-rework`
branch and measure how much of `strength.go`, the per-generator `Matches`
implementations, and `KeyPairGeneratorFromAPI` collapses.
