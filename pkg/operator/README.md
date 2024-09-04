
### APIService
**Location** [apiserver/controller/apiservice](https://github.com/openshift/library-go/tree/master/pkg/operator/apiserver/controller/apiservice)

Creates and maintains an `apiservices.apiregistration.k8s.io`.

### ResourceSyncController
**Location** [resourcesynccontroller](https://github.com/openshift/library-go/tree/master/pkg/operator/resourcesynccontroller)

Copies a ConfigMap or Secret from one location to another.
Can copy partial ConfigMaps or Secrets.

### StaticResourceController
**Location** [staticresourcecontroller](https://github.com/openshift/library-go/tree/master/pkg/operator/staticresourcecontroller)

Creates, maintains, and deletes resources that need little to no customization.
Has precondition capability for things like FeatureGates, platforms, or whatever you want.

