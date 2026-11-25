# AI Agent Instructions for library-go

library-go is a shared Go library for OpenShift controllers and operators. See the [README package guide](README.md#find-the-package-for-your-task) for where to start.

## Critical Rules

1. **Never add imports from `k8s.io/kubernetes` or `openshift/origin`.** This is an absolute constraint — the library must remain independent of those repos.
2. **Always run `go mod tidy && go mod vendor` after any dependency change.** The vendor directory is checked in and CI validates it.
3. **Verification.** Before committing, check Markdown for prose edits or check formatting and test affected Go packages, for example with `make test-unit GO_TEST_PACKAGES=./pkg/controller/factory`. For broad changes, run `make verify` and `make test-unit` before submitting the PR.
4. **Public APIs.** Preserve compatibility where practical. For breaking changes, assess the impact on consumers and document how they should migrate.
5. **Proof PRs.** Before merging a library-go PR, open a companion PR in at least one consuming repository that bumps library-go to the proposed change and runs the consumer's presubmits. For code changes, make sure those presubmits exercise the new or changed code.

## What NOT to Do

- Do not add new top-level packages without a strong reason — the bar for inclusion is high.
- Do not modify OWNERS or OWNERS_ALIASES files.
- Do not use Kubernetes code generators (deepcopy-gen, client-gen, informer-gen). Some CRD manifests are synced from `openshift/api` via the Makefile, but the Go code is hand-written.
- Do not add test dependencies on real cloud providers or external services in unit tests. Use fakes and mocks from `k8s.io/client-go/kubernetes/fake`.
