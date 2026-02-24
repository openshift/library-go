# KMS Mock Plugin Key Generation

Generates a SoftHSM token with AES-256 key for the KMS mock plugin.

## Why?

Keys from `pkcs11-tool --keygen` have proper PKCS#11 attributes for AES-GCM.
Keys from `softhsm2-util --import` lack these and fail with `CKR_MECHANISM_INVALID`.

## Generate Token

```bash
./generate.sh
```

Copy output to `softhsm-tokens.tar.gz.b64` in `../assets/k8s_mock_kms_plugin_configmap.yaml`.
