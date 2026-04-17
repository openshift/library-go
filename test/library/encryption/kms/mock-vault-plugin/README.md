# mock-vault-kms

A wrapper around the upstream [Kubernetes mock KMS plugin](https://github.com/kubernetes/kms/tree/main/internal/plugins/_mock)
that adds HashiCorp `vault-kube-kms` flag compatibility.

The wrapper binary (`/vault-kube-kms`) accepts all vault-kube-kms flags, translates
the relevant ones, and `exec`s the upstream `mock-kms-plugin` binary. This allows the
OpenShift encryption operator to use this image as a drop-in `VaultImage` without a
Vault Enterprise license.

## How it works

```
Operator passes Vault flags via sidecar injection
        │
        ▼
/vault-kube-kms                              (this wrapper)
  --listen-address=unix://...        →  translates to -listen-addr
  --vault-address=...                →  dropped
  --transit-key=...                  →  dropped
  ...                                →  dropped
        │
        ▼  syscall.Exec
/usr/local/bin/mock-kms-plugin               (upstream Kubernetes mock)
  -listen-addr=unix://...
  -config-file-path=/etc/softhsm-config.json (baked into image)
        │
        ▼
SoftHSM / PKCS#11 encryption on unix socket
```

- Wrapper is a static Go binary (~2MB, no CGO)
- Base image is the upstream `quay.io/openshifttest/mock-kms-plugin` (Alpine + SoftHSM)
- Encryption is handled by upstream mock via SoftHSM/PKCS#11
- **Self-contained**: SoftHSM config and pre-generated tokens are baked into the image; no init container or external ConfigMap is needed

## Accepted flags

All flags match the HashiCorp `vault-kube-kms` binary exactly:

| Flag | Action |
|------|--------|
| `--listen-address` | Translated to `-listen-addr` and passed to upstream |
| `--timeout` | Passed through to upstream |
| `--vault-address` | Accepted, dropped |
| `--vault-namespace` | Accepted, dropped |
| `--vault-connection-timeout` | Accepted, dropped |
| `--transit-mount` | Accepted, dropped |
| `--transit-key` | Accepted, dropped |
| `--auth-method` | Accepted, dropped |
| `--auth-mount` | Accepted, dropped |
| `--approle-role-id` | Accepted, dropped |
| `--approle-secret-id-path` | Accepted, dropped |
| `--tls-ca-file` | Accepted, dropped |
| `--tls-sni` | Accepted, dropped |
| `--tls-skip-verify` | Accepted, dropped |
| `--log-level` | Accepted, dropped |
| `--metrics-port` | Accepted, dropped |
| `--disable-runtime-metrics` | Accepted, dropped |

## Building

```bash
./build-from-source.sh
```

Override image coordinates:

```bash
REGISTRY=quay.io REPO=openshifttest IMAGE_NAME=mock-kms-plugin-vault TAG=v1 ./build-from-source.sh
```

The Dockerfile is multi-stage:
1. Builds the wrapper binary from Go source
2. Generates SoftHSM tokens (Alpine + softhsm + opensc)
3. Copies wrapper, config, and tokens into `quay.io/openshifttest/mock-kms-plugin`

## Running standalone

```bash
podman run --rm -it quay.io/rhn_support_rgangwar/mock-kms-plugin-vault:latest \
  -listen-address=unix:///tmp/kmsplugin/kms.sock \
  -vault-address=https://vault.example.com \
  -transit-key=my-key \
  -approle-role-id=1234
```

## Running as VaultImage

The operator reads `VaultImage` from the APIServer CRD and injects the
KMS plugin as a sidecar into API server pods:

```bash
oc patch apiserver cluster --type=merge -p '{
  "spec": {
    "encryption": {
      "type": "KMS",
      "kms": {
        "vaultImage": "quay.io/rhn_support_rgangwar/mock-kms-plugin-vault:latest"
      }
    }
  }
}'
```

The operator passes Vault flags — the wrapper translates and exec's the upstream mock.

## TODO

- Automate image builds in CI
- Add multi-arch support (arm64)
