# Static Pod Controllers

OpenShift 4.x deploys the following foundational components as [static
pods](https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/):

- etcd
- kube-apiserver
- kube-controller-manager
- kube-scheduler

These components comprise the minimum control plane on which all other
OpenShift components are hosted.

The operators that manage these foundational components rely on the
set of controllers found in the `pkg/operator/staticpod` package and
its children. These controllers are collectively responsible for
generating static pod manifests and related configuration and writing
them to the static pod manifests (`/etc/kubernetes/manifests`) and
static pod resources (`/etcd/kubernetes/static-pod-resources`) paths,
respectively, on each control plane node.

The controllers take as input resources read from the OpenShift
API. That means these controllers won't work without an
apiserver. Installation of a new cluster involves creating bootstrap
versions of the foundational components before these controllers can
take over.

## High-level flow

A given operator (e.g. `cluster-kube-apiserver-operator`) configures a
set of static pod controllers via the `staticpod` package's
`NewBuilder` function and associated `With*` methods. Configuration includes:

 - the set of configmaps and secrets containing configuration data for
   the static pod
   - the first configmap is expected to contain the static pod
 - the set of configmaps and secrets containing ca bundles and tls certs
   - resources containing tls data are supplied separately from other
     resources to allow reload without restart/redeploy of the static pod
 - the operator namespace

A static pod rollout occurs as follows:

 - the revision controller determines that a new revision is
   required. Triggers include:
   - no revision is present
   - the watched resources have changed since the current revision
   - rollout has been manually triggered by setting
     forceRedeploymentReason in the operator config
 - the installer controller creates an installer pod for the new
   revision for each control plane node
   - the image of the installer pod is typically the operator image
     and the command defined by the operator
 - each installer pod copies the resources and static pod manifest for
   the current revision to the host filesystem
 - the installer state controller watches the installer pods for
   indications of failure and records any problem in operator status
 - the static pod state controller watches static pods for indications
   of failure and records any problem in operator status

## Status

The static pod controllers record status in the following resources:

 - Operator config
   - e.g. operator.openshift.io/v1:KubeAPIServer/cluster
   - used by the operator to track its state
     - operator-specific conditions
     - static pod accounting e.g.
       - latestAvailableRevision
       - nodeStatuses

 - Cluster operator status
   - e.g. config.openshift.io/v1:ClusterOperator/kube-apiserver
   - used by the operator to convey its state to the cluster
     - degraded/progressing/available conditions
     - relatedObjects
       - used by must-gather to know what to collect
     - records component versions

### Revision

[Controller Definition](../revisioncontroller/revision_controller.go)

 - copies tracked secrets and configmaps when they change
   - the name of the copied resources is suffixed with the new revision
   - ensures that installer pods can copy the resources for a revision
     without fear of them changing during the rollout
 - maintains 'revision' configmaps indicating status of a given revision
   - allows determining what the current revision is
   - provides status to the prune controller

### Installer

[Controller Definition](controller/installer/installer_controller.go)

 - creates installer pod per control plane node for a given revision
 - watches statis pod controllers for evidence that a new revision is required

### Installer State

[Controller Definition](controller/installerstate/installer_state_controller.go)

 - watches installer pods in the operand namespace
 - records in operator status if pod are pending for more than a max duration
   - pod pending
   - pod container waiting
   - failed to create pod network

### Static Pod State

[Controller Definition](controller/staticpodstate/staticpodstate_controller.go)

 - watches static pods in the operand namespace
 - sets 'StaticPodsDegraded' condition

### Prune

[Controller Definition](controller/prune/prune_controller.go)

 - ensures a maximum number of revisioned resources by removing old
   revisioned resources

### Node

[Controller Definition](controller/node/node_controller.go)

 - updates MasterNodesReady operator status condition
 - sets StaticPodOperatorStatus in operator status e.g.
   - latestAvailableRevision
   - latestAvailableRevisionReason
   - nodeStatuses
     - nodeName
     - currentRevision
     - targetRevision
     - lastFailedRevision
     - lastFailedRevisionErrors

### Static Resource

[Controller Definition](../staticresourcecontroller/static_resource_controller.go)

 - applies static manifests required by installer pods
   - service account
   - cluster role binding

### Unsupported Config Overrides

[Controller Definition](../unsupportedconfigoverridescontroller/unsupportedconfigoverrides_controller.go)

 - sets `UnsupportedConfigOverridesSet` condition in operator status
   if `spec.unsupportedConfigOverrides` is not empty
 - has nothing to do with deployment of static pods.

### Cluster Operator Logging

[Controller Definition](../loglevel/logging_controller.go)

 - supports changing the klog logging level for the operator via a
   value specified in the operator config
 - has nothing to do with deployment of static pods.
