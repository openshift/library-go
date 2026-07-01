# Architecture: library-go

## Overview

library-go is the shared foundation library for OpenShift. It provides reusable components that are vendored by dozens of OpenShift operators and control plane components. The library is organized around several major subsystems, each addressing a core operational concern.

**Design philosophy:** Code must have concrete use cases in at least two separate OpenShift repositories. The library must not depend on `k8s.io/kubernetes` or `openshift/origin`, keeping it lightweight and broadly reusable.

## Major Subsystems

### Operator Controller Framework (`pkg/operator/`)

The largest subsystem (~33 subpackages). Provides the building blocks that most OpenShift operators are built on.

Key components:

- **ConfigObserver** (`configobserver/`) — Watches multiple configuration inputs (configmaps, secrets, API resources) and synthesizes them into a single `RawExtension` output. Change detection works by comparing the merged observer output against the existing observed config. This is the standard pattern for operators that need to react to configuration changes from multiple sources.

- **ResourceSyncController** (`resourcesynccontroller/`) — Synchronizes secrets and configmaps across namespaces. Supports partial sync (specific keys only). Used by operators that need configuration or credentials from one namespace available in another.

- **StaticPodController** (`staticpod/`) — Manages static pod lifecycle with revision tracking and atomic directory swaps. Uses `renameat2(RENAME_EXCHANGE)` on Linux for atomic operations; non-Linux platforms are not supported and return an error. Includes installers, pruners, and readiness checks.

- **RevisionController** (`revisioncontroller/`) — Tracks configuration revisions to enable rollback and audit trails for static pod operators.

- **StatusController** (`status/`) — Aggregates status conditions from multiple sources into a unified `ClusterOperator` status. Handles degraded, progressing, and available conditions.

- **ManagementStateController** (`managementstatecontroller/`) — Handles the `Managed`/`Unmanaged`/`Removed` lifecycle states for operators.

### Encryption and KMS (`pkg/operator/encryption/`)

Complex subsystem (11 subdirectories) that manages encryption of Kubernetes resources at rest in etcd.

Architecture:

- **State machine** (`statemachine/`) — Drives encryption through states: unencrypted → key exists → migration in progress → encrypted. Preconditions gate transitions.
- **Controllers** (`controllers/`) — Coordinate key creation, migration, and pruning.
- **Crypto providers** (`crypto/`) — Pluggable encryption providers (AES-CBC, AES-GCM, KMS v1/v2, secretbox).
- **Deployer** (`deployer/`) — Applies encryption configuration to API server pods.

The KMS integration supports both KMS v1 and v2 protocols, with preflight checks to validate provider connectivity before enabling encryption.

### Certificate Management

Dual-layer design:

- **`pkg/crypto/`** — Low-level primitives: TLS certificate generation, key pair creation (RSA 2048+, ECDSA P256/P384/P521), cipher suite management, certificate filtering and rotation logic. Enforces TLS adherence policies.

- **`pkg/operator/certrotation/`** — High-level controller that manages certificate lifecycle. Monitors expiry and triggers rotation at 80% of validity (4/5 of the cert lifetime). Maintains certificate chains across rotation events. Note: CSR handling is in `pkg/operator/csr/`, not here.

- **`pkg/pki/`** — Newer API-driven PKI profile system. Provides a `PKIProfile` abstraction that allows cluster-wide key algorithm policies to be applied consistently across all certificate operations.

### Manifest-Based Client (`pkg/manifestclient/`)

An alternative to traditional generated Kubernetes clients. Operates on embedded manifests with a discovery reader, enabling offline operation and simpler dependency chains. Used in contexts where full API server connectivity is not available or desirable.

### Configuration (`pkg/config/`)

Provides configuration management utilities: serving info setup, cluster operator status handling, leader election configuration, and configuration validation. Used by operators during initialization.

## Dependency Architecture

```text
library-go
├── depends on
│   ├── k8s.io/api, apimachinery, client-go, apiserver
│   ├── github.com/openshift/api          (OpenShift type definitions)
│   ├── github.com/openshift/client-go    (generated OpenShift clients)
│   └── go.etcd.io/etcd/client/v3         (encryption/KMS operations)
│
├── consumed by
│   ├── cluster-image-registry-operator
│   ├── cluster-authentication-operator
│   ├── cluster-kube-apiserver-operator
│   ├── cluster-openshift-apiserver-operator
│   └── ... (dozens of OpenShift operators)
│
└── must NOT depend on
    ├── k8s.io/kubernetes
    └── openshift/origin
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| No `k8s.io/kubernetes` dependency | Keeps the library vendorable without pulling in the entire Kubernetes monorepo. Maintains a manageable dependency tree. |
| ConfigObserver produces RawExtension | Decouples configuration observation from consumption. Observers can be composed independently without knowing each other's schemas. |
| Atomic static pod swaps | Prevents partial state during pod updates. A failed swap leaves the previous revision intact rather than producing a broken intermediate state. |
| Dual crypto/PKI layers | `pkg/crypto` handles raw operations while `pkg/pki` adds policy. Separating these allows operators to use low-level crypto without buying into the full PKI profile system. |
| Vendor directory checked in | Ensures reproducible builds across CI and developer machines without network access to module proxies. Standard practice for OpenShift repos. |
| No Kubernetes code generators | Does not use deepcopy-gen, client-gen, or informer-gen. Some CRD manifests are synced from openshift/api via the Makefile. Keeps the library explicit and auditable. |

## Testing Architecture

- **Unit tests** — Colocated with source (`*_test.go`). Use Kubernetes fake clientsets for API simulation.
- **E2E encryption tests** (`test/e2e-encryption/`) — Validate full encryption lifecycle including KMS provider interaction. Require etcd and KMS sidecar infrastructure.
- **E2E monitoring tests** (`test/e2e-monitoring/`) — Validate metrics collection and alerting integration.
- **Shared test helpers** (`test/library/`) — Reusable test utilities for encryption, metrics, and API server testing.
