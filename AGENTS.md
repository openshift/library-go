# AI Agent Instructions for library-go

## What This Repo Is

library-go is a shared Go helper library consumed by dozens of OpenShift operators and components. It provides reusable building blocks: operator controller framework, certificate management, configuration observers, encryption/KMS integration, manifest-based clients, and more.

**This is a library, not an application.** There is no main binary. Changes here affect every OpenShift component that vendors this repo.

## Critical Rules

1. **Never add imports from `k8s.io/kubernetes` or `openshift/origin`.** This is an absolute constraint — the library must remain independent of those repos.
2. **Always run `go mod tidy && go mod vendor` after any dependency change.** The vendor directory is checked in and CI validates it.
3. **Run `make verify` and `make test-unit` before considering any change complete.**
4. **Do not introduce breaking API changes** to existing public functions or types without explicit direction. Dozens of repos depend on these interfaces.

## Repository Structure

```text
pkg/
├── operator/          # Controller framework (33 subpackages) — the core of the library
│   ├── certrotation/  # Certificate lifecycle and rotation controllers
│   ├── configobserver/ # Watches config inputs, produces RawExtension outputs
│   ├── encryption/    # KMS/encryption state machine (11 subdirs) — very complex
│   ├── staticpod/     # Static pod management with atomic directory swaps
│   ├── resourcesynccontroller/ # Cross-namespace secret/configmap sync
│   └── ...
├── crypto/            # Low-level TLS, certificates, key generation, cipher suites
├── pki/               # High-level API-driven PKI profiles (newer)
├── config/            # Configuration management, serving, leader election
├── manifestclient/    # Manifest-based client operations (offline-capable)
├── controller/        # Controller utilities, factory, file observer
├── assets/            # Asset creation and templating
└── ...                # 35+ top-level packages total
test/
├── e2e-encryption/    # Encryption end-to-end tests
├── e2e-monitoring/    # Monitoring end-to-end tests
└── library/           # Shared test helpers
```

## Key Patterns to Follow

- **ConfigObserver pattern**: Controllers watch multiple config inputs and produce a single `RawExtension` output. Changes are detected by comparing the merged observer output against the existing observed config. Follow this pattern for any new observer.
- **Preconditions over defaults**: `StaticResourceController` uses preconditions (feature gates, platform checks) to decide behavior. Do not try to handle all combinations with defaults.
- **Controller naming**: Controllers follow the pattern `NewXxxController(...)` returning a `factory.Controller`. Follow existing naming and constructor conventions.

## High-Risk Areas — Proceed with Caution

- **`pkg/operator/encryption/`** — State machine with complex preconditions, crypto providers, KMS plugin integration, and etcd encryption config management. Do not modify without deep understanding.
- **`pkg/crypto/`** and **`pkg/operator/certrotation/`** — Certificate rotation triggers at 80% of validity (4/5 of cert lifetime) and handles multi-CA chain support. Subtle bugs here cause cluster outages. Note: CSR handling is in `pkg/operator/csr/`, not in certrotation.
- **`pkg/operator/staticpod/`** — Atomic directory swaps use `renameat2(RENAME_EXCHANGE)` on Linux; non-Linux platforms are not supported and return an error. Platform-specific code needs careful testing.

## Build and Test

```bash
make build       # Compile all packages
make test-unit   # Run unit tests
make verify      # Linters, gofmt, vet
```

## What NOT to Do

- Do not add new top-level packages without a strong reason — the bar for inclusion is high.
- Do not modify OWNERS or OWNERS_ALIASES files.
- Do not use Kubernetes code generators (deepcopy-gen, client-gen, informer-gen). Some CRD manifests are synced from `openshift/api` via the Makefile, but the Go code is hand-written.
- Do not add test dependencies on real cloud providers or external services in unit tests. Use fakes and mocks from `k8s.io/client-go/kubernetes/fake`.
