# k8s-mock-kms-plugin

Builds the Kubernetes mock KMS plugin image from upstream source
and layers a thin wrapper binary on top.

The final image contains both:
- `/usr/local/bin/mock-kms-plugin` — the upstream binary (unchanged)
- `/usr/local/bin/vault-kube-kms` — wrapper that accepts extra flags and execs the upstream binary

## Building

```bash
./build-from-k8s.sh
```

Builds and tags as `k8s-mock-kms-plugin`.

Optionally specify a different Kubernetes branch:

```bash
K8S_BRANCH=release-1.34 ./build-from-k8s.sh
```

## Wrapper

The wrapper initializes SoftHSM from embedded assets, validates
flags, and execs the upstream binary.

```bash
vault-kube-kms -vault-address=https://vault.example.com -listen-address=unix:///var/run/kmsplugin/kms.sock
```

## Pushing to registry

```bash
docker tag k8s-mock-kms-plugin quay.io/polynomial/k8s-mock-kms-plugin:latest
docker push quay.io/polynomial/k8s-mock-kms-plugin:latest
```

## TODO

- Automate image builds (CI in openshift/origin?)
- Publish to quay.io/openshifttest
