# Proposal: `crypto.KeySpec` — separate key parameters from key generation

**Status:** Prototyped — see "Prototype results" below
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

## Design decisions

The prototype resolved the open decisions as follows; each held up in
practice:

### Flat struct vs. sealed interface

**Flat struct.** It mirrors the API's discriminated `PKIKeyConfig`, supports
`==` (which the resolution tests now lean on directly), and gives
`KeyAlgorithm` its purpose. The cost — invalid combinations are
representable — is contained by `Validate`, and turned out to be cheap:
the whole validation surface is four error strings.

### Whether `Matches` stays on `KeyPairGenerator`

**It stays.** `Matches` is upstream API (#2550); the built-in generator
delegates to `spec.Matches`, and `KeySpec.Matches` is available as the
data-level path for new code. `SecurityLevel()` however came *off* the
interface — strength is a property of the spec, and keeping it off the
interface removes #2584's breakage of out-of-tree implementers.

### Where it lands

The prototype is built on #2584's tip (`fbd35e47f`), which is where the
change belongs: it is a crypto-layer change, #2584 is already reworking
`pkg/crypto`, and `KeySpec` subsumes #2584's `SecurityLevel()`-on-interface
design (the `SecurityLevel` *type* and its `Compare` are kept as-is; only
the interface method moves to `KeySpec`).

Changing `CertificateConfig.Key` (and, on `configurable-pki`,
`Resolved*Config.Key`) from `KeyPairGenerator` to `KeySpec` is a Tech Preview
break in the same category as the already-accepted
`ResolveCertificateConfig` signature change. The CKAO and service-ca proof
PRs should still be checked for direct use of `cfg.Key`.

### Naming

`KeySpec`. It reads well at every call site the prototype produced
(`cfg.Key.KeyPairGenerator()`, `crypto.StrongerKeySpec`, `keySpec.Algorithm != ""`).

## Prototype results

A working prototype is committed as `37aa4bb26` on branch
`worktree-keyspec-proposal` (worktree
`.claude/worktrees/keyspec-proposal`), based on #2584's tip. All crypto, pki,
and certrotation tests pass; the only failure, `TestConstantMaps`, is
pre-existing on that base (local Go toolchain newer than the branch's TLS
constant maps).

### What the API became

The sketch above survived almost unchanged. The realized surface:

```go
type KeySpec struct {
    Algorithm  KeyAlgorithm
    RSABits    int
    ECDSACurve ECDSACurve
}
func (s KeySpec) Validate() error
func (s KeySpec) KeyPairGenerator() (KeyPairGenerator, error)
func (s KeySpec) SecurityLevel() SecurityLevel
func (s KeySpec) String() string
func (s KeySpec) Matches(pub crypto.PublicKey) error
func KeySpecFromPublicKey(pub crypto.PublicKey) (KeySpec, error)
func StrongerKeySpec(a, b KeySpec) KeySpec
```

plus `MinRSAKeySize` moved here as the floor constant.

### What collapsed

- The two per-algorithm generator types became **one unexported
  `keyPairGenerator{spec}`**: `keygen_rsa.go` went from 79 to 20 lines,
  `keygen_ecdsa.go` from 91 to 47. The per-generator `Matches`,
  `SecurityLevel`, zero-value-default, and constructor-validation logic
  all reduced to spec operations.
- `pkg/pki`'s `selfCheckingKeyPairGenerator` is **deleted** (`resolve.go`
  went from 113 to 78 lines) — the self-check moved into
  `KeySpec.KeyPairGenerator()`, where the generator is constructed, and now
  covers every consumer rather than only pki resolution.
- `pki.KeyPairGeneratorFromAPI` became `pki.KeySpecFromAPI`, a field mapping
  with one validation call.
- `StrongerKeySpec` is two `SecurityLevel` comparisons and a field check —
  the closed-world type switch and the `ECDSAKeyPairGenerator`
  type-assertion tie-break are gone.

### What the consumers look like now

- **Resolution is pure data.** `CertificateConfig.Key` is a `KeySpec`, so
  `ResolveCertificateConfig` results can be compared with `==`, printed
  (`"ECDSA P384"`), logged, and strength-ranked by any consumer. The pki
  resolve tests shrank from "generate a key, then match it" to
  `cfg.Key != want`.
- **Certrotation derives the generator at the point of use.**
  `resolveKeySpecWithFallback` returns a zero `KeySpec` for Unmanaged
  (checked via `Algorithm != ""`, replacing the nil-generator convention),
  and both generation sites call `keySpec.KeyPairGenerator()` inline.
- The interface `KeyPairGenerator` shrank back to `GenerateKeyPair` +
  `Matches`, so consumer test fakes that #2584 would have broken keep
  compiling.

### Behavior changes to be aware of

- The upstream `Bits: 0 → 2048` implicit default for RSA is **gone**: a zero
  `RSABits` is invalid at `KeyPairGenerator()`. This matches the
  configurable-pki direction but is a real change for any master consumer
  relying on `RSAKeyPairGenerator{}`.
- `pki.brokenKeyPairGenerator` (the test proving the self-check catches a
  lying generator) was removed with the wrapper: pki can no longer inject
  generators into resolution at all, which is the point. The equivalent
  guarantee is covered by crypto's cross-product `Matches` tests plus the
  in-constructor self-check.
- Net diff vs `fbd35e47f`: −493/+687 lines, of which 153 are the new
  `keyspec_test.go` coverage (`Validate` cases, `String`, public-key
  round-trips, `StrongerKeySpec` ordering, constructor rejection of invalid
  specs); the rest of the additions are `keyspec.go` itself (184 lines) and
  the spec-driven test conversions.

## Next step

Decide whether to fold this into #2584 (replacing its
`SecurityLevel()`-on-interface commits) or land it as a follow-up; then check
the CKAO and service-ca proof PRs for direct use of `cfg.Key` as a generator
before porting the `Resolved*Config.Key` type change onto `configurable-pki`.
