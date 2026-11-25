# library-go

`github.com/openshift/library-go` provides shared Go packages for building OpenShift controllers and operators. Use it to wire reconcile loops, turn cluster configuration into component configuration, and manage the resources your OpenShift operator owns.

## Find the package for your task

| I need to… | Start here |
| --- | --- |
| Build an informer-driven controller | [`factory`](pkg/controller/factory) handles cache synchronization, work queues, and retries. |
| Reconcile Kubernetes resources | [`resourceapply`](pkg/operator/resource/resourceapply) provides create and update helpers for supported types. For resources defined by mostly static manifests, [`staticresourcecontroller`](pkg/operator/staticresourcecontroller) handles reconciliation. |
| Derive component configuration from cluster state | [`configobserver`](pkg/operator/configobserver) combines observer outputs into the operator's `spec.observedConfig`. Give each output field a single observer. See the existing observers for proxy, TLS, and feature gates. |
| Report operator health and versions | [`v1helpers`](pkg/operator/v1helpers) helps update operator status and conditions. [`status`](pkg/operator/status) publishes conditions and versions on the cluster-scoped `ClusterOperator` resource. |
| Copy a Secret or ConfigMap across namespaces | [`resourcesynccontroller`](pkg/operator/resourcesynccontroller) keeps the destination in sync with the source. |

The [operator package guide](pkg/operator/README.md) describes additional controllers.

## Contributing

- **Shared use.** New helpers should solve a substantial problem with concrete use cases in at least two OpenShift repositories.
- **Compatibility** Preserve compatibility where practical; breaking changes are acceptable when warranted but must be called out so consuming operators can update.
- **Dependencies.** Justify new dependencies and update `vendor/` when dependencies change. Never depend on `k8s.io/kubernetes` or `openshift/origin`.
- **Backports.** For fixes likely to be backported, avoid newer Go language features and standard library APIs when practical. Older OpenShift branches may use older Go versions.
- **Proof PRs.** Open a companion PR in at least one consuming repository that bumps library-go to your change and runs that repository's presubmits. This verifies the change in a consumer before it merges.
