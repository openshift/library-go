# Contributing to library-go

library-go is a shared Go helper library for OpenShift. It provides reusable, production-grade components for operators, API servers, certificate management, and more. Because it is imported by dozens of OpenShift repositories, changes here have wide impact and are held to a high bar.

## Before You Start

- **High bar for inclusion.** New code must have concrete use cases in at least two separate OpenShift repositories and be of reasonable complexity.
- **No forbidden imports.** This repo must not depend on `k8s.io/kubernetes` or `openshift/origin`. PRs that add either will be rejected.

## Development Workflow

1. Fork the repo and clone your fork.
2. Create a feature branch from `master`.
3. Make your changes, add or update tests.
4. Run verification locally before pushing:

```bash
make build          # Compile all packages
make test-unit      # Run unit tests
make verify         # Run linters, gofmt, vet
```

5. If you changed dependencies, update the vendor directory:

```bash
go mod tidy && go mod vendor
```

The vendor directory is checked in. Never skip this step — CI will fail if vendor is stale.

6. Push your branch and open a PR against `openshift/library-go:master`.

## Pull Request Guidelines

- Keep PRs focused. One logical change per PR.
- Write clear commit messages. Follow existing conventions:
  - `UPSTREAM: <carry>` or `UPSTREAM: <drop>` for upstream-related changes
  - Reference Jira tickets where applicable (e.g., `OCPBUGS-12345: fix cert rotation race`)
- Include unit tests for new functionality. For operator controller changes, consider e2e test coverage.
- PRs require approval from at least one approver listed in the `OWNERS` file.

## PR Review Rules

- All PRs require `/lgtm` from a reviewer and `/approve` from an approver (OWNERS file). These are separate roles — the approver confirms the change belongs in the repo, the reviewer confirms correctness.
- Prow enforces required labels: `lgtm` and `approved` must both be present before merge.
- CI checks (`make verify`, `make test-unit`) must pass. Reviewers should not `/lgtm` a PR with failing CI.
- Review for backward compatibility — this is a shared library. Ask: "will this break any downstream consumer?" If unclear, request the author demonstrate that existing callers still compile and pass tests.
- Changes to high-risk areas (encryption, certrotation, staticpod) should be reviewed by someone familiar with that subsystem. Check the per-directory OWNERS files for the right reviewers.
- Carry patches (`UPSTREAM: <carry>`) require extra scrutiny — they must be rebased on every upstream rebase and justified in the commit message.
- Do not approve PRs that add `k8s.io/kubernetes` or `openshift/origin` imports under any circumstance.

## Testing

| Command | What it runs |
|---------|-------------|
| `make test-unit` | Unit tests across `./pkg/...` |
| `make test-e2e-encryption` | Encryption/KMS end-to-end tests |
| `make test-e2e-monitoring` | Monitoring end-to-end tests |
| `make verify` | Linters, format checks, vet |

Unit tests live alongside source files (`*_test.go`). Shared test helpers are in `test/library/`.

## Code Conventions

- Follow standard Go conventions (gofmt, govet).
- Use the existing patterns in the package you are modifying — library-go has well-established patterns for controllers, observers, and resource sync.
- Keep API-facing changes backward compatible. Breaking changes require discussion with approvers.

## Areas Requiring Extra Care

- **Encryption / KMS** (`pkg/operator/encryption/`): Complex state machine with preconditions, observer patterns, and KMS plugin integration. Changes here need deep familiarity with the subsystem.
- **Certificate rotation** (`pkg/crypto/`, `pkg/operator/certrotation/`): Involves expiry checks (rotation at 80% of validity) and multi-CA chain handling. CSR logic is in `pkg/operator/csr/`. Test thoroughly.
- **Static pod management** (`pkg/operator/staticpod/`): Uses `renameat2(RENAME_EXCHANGE)` for atomic directory swaps on Linux; non-Linux is not supported. Be careful with platform-specific code.

## CI

CI runs via OpenShift's CI infrastructure (Prow / ci-operator). The build root image is defined in `.ci-operator.yaml`. All `make verify` and `make test-unit` checks must pass for a PR to merge.

## Questions?

If you are unsure whether a change belongs in library-go, open an issue first to discuss. The approvers can help determine if this is the right home for your contribution.
