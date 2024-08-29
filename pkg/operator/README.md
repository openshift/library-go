
### APIService
**Location** [apiserver/controller/apiservice](https://github.com/openshift/library-go/tree/master/pkg/operator/apiserver/controller/apiservice)

Creates and maintains an `apiservices.apiregistration.k8s.io`.


### StaticResourceController
**Location** [staticresourcecontroller](https://github.com/openshift/library-go/tree/master/pkg/operator/staticresourcecontroller)

Creates, maintains, and deletes resources that need little to no customization.
Has precondition capability for things like FeatureGates, platforms, or whatever you want.
