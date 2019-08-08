#!/bin/bash
set -euo pipefail

GLIDE=${GLIDE:-glide}

readonly GLIDE_MINOR_VERSION="13"
readonly REQUIRED_GLIDE_VERSION="0.$GLIDE_MINOR_VERSION"

function verify_glide_version() {
	if ! command -v ${GLIDE} &> /dev/null; then
		echo "[FATAL] Glide was not found in \$PATH. Please install version ${REQUIRED_GLIDE_VERSION} or newer."
		exit 1
	fi

	local glide_version
	glide_version=($(${GLIDE} --version))
	if ! echo "${glide_version[2]#v}" | awk -F. -v min=$GLIDE_MINOR_VERSION '{ exit $2 < min }'; then
		echo "Detected glide version: ${glide_version[*]}."
		echo "Please install Glide version ${REQUIRED_GLIDE_VERSION} or newer."
		exit 1
	fi
}

verify_glide_version

${GLIDE} update --strip-vendor

# glide doesn't handle mercurial properly and leaves internal files (equivalent of .git/) laying around
# Given those files differ by mercurial version it was cloned with, verify-deps would break
find ./vendor -name '.hg_archival.txt' -delete
