# library-go

Shared Go library for OpenShift controllers and operators.

## Commands

- Targeted unit tests: `make test-unit GO_TEST_PACKAGES=./pkg/controller/factory`
- All unit tests: `make test-unit`
- Verify (gofmt, govet, golang version): `make verify`

## Rules

- **Go features**: For changes likely to be backported to older OpenShift releases that use older Go versions, avoid newer Go language/stdlib features when practical.
- **Dependencies**: Any dependency or top-level change affects every consumer and requires strong justification; after changing deps run `go mod tidy && go mod vendor` and `make verify-deps`.
- **Unit test isolation**: Never depend on live clusters, cloud providers, or external services in unit tests. Use `k8s.io/client-go/kubernetes/fake`.
- **Breaking changes**: Prefer a clean design over backwards compatibility—breaking a public API is fine when warranted; just call out the change so consuming operators can be updated.
- **Incremental changes**: Build larger work as a series of logical commits (or separate PRs) that each compile and pass tests, rather than one big change.
- **Proof PRs**: Before merging, open a companion PR in at least one consuming repository that bumps library-go to your change and runs that repository's presubmits; for code changes, make sure those presubmits exercise the new or changed code.
