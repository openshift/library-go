FROM alpine:latest

RUN apk add --no-cache softhsm opensc jq yq

WORKDIR /var/lib/softhsm/tokens

COPY <<EOF /entrypoint.sh
#!/bin/sh
set -e
CONFIG=\$(yq -r '.data."softhsm-config.json"' /configmap.yaml)
TOKEN_LABEL=\$(echo "\$CONFIG" | jq -r '.TokenLabel')
PIN=\$(echo "\$CONFIG" | jq -r '.Pin')
MODULE_PATH=\$(echo "\$CONFIG" | jq -r '.Path')
softhsm2-util --init-token --free --label "\$TOKEN_LABEL" --pin "\$PIN" --so-pin "\$PIN" >&2
pkcs11-tool --module "\$MODULE_PATH" --keygen --key-type aes:32 --token-label "\$TOKEN_LABEL" --label kms-test --pin "\$PIN" >&2
echo "" >&2
echo "=== Copy below to softhsm-tokens.tar.gz.b64 in ../assets/k8s_mock_kms_plugin_configmap.yaml ===" >&2
tar czf - . | base64
EOF

RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
