# library-go
Helpers for going from apis and clients to useful runtime constructs.  `config.ServingInfo` to useful serving constructs is the canonical example.  Anything introduced here must have concrete use-cases in at least two separate openshift repos and be of some reasonable complexity.  The bar here is high.  We'll start with openshift/api-review as the approvers.

This repo **must not depend on k8s.io/kubernetes or openshift/origin**.

## Proof PRs

Changes to library-go must be accompanied by "proof PRs" that bump this dependency in at least one consuming repo and run presubmits there. This validates that the change works correctly in context before merging.
