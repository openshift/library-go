# k8s-mock-kms-plugin

Builds the Kubernetes mock KMS plugin image from upstream source.

## Building

```bash
./build-from-k8s.sh
```

Builds and tags as `k8s-mock-kms-plugin`.

Optionally specify a different Kubernetes branch:

```bash
K8S_BRANCH=release-1.34 ./build-from-k8s.sh
```

## Pushing to registry

```bash
docker tag k8s-mock-kms-plugin quay.io/polynomial/k8s-mock-kms-plugin:latest
docker push quay.io/polynomial/k8s-mock-kms-plugin:latest
```

## TODO

- Automate image builds (CI in openshift/origin?)
- Publish to quay.io/openshifttest
