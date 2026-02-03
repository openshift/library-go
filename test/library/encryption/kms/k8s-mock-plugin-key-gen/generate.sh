#!/usr/bin/env bash
set -euo pipefail

docker build -t softhsm-keygen .
docker run --rm -v "$(pwd)/../assets/k8s_mock_kms_plugin_configmap.yaml:/configmap.yaml:ro" softhsm-keygen
