#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    echo "Usage: $0 [--push] <connector-dir> <version>" >&2
    echo "  --push         Push the image after building" >&2
    echo "  connector-dir  Path to the connector (e.g. external-import/crowdstrike)" >&2
    echo "  version        Image version tag" >&2
    exit 1
}

PUSH=false
if [ "$1" = "--push" ]; then
    PUSH=true
    shift
fi

CONNECTOR_DIR="${1:?$(usage)}"
VERSION="${2:?$(usage)}"

# Resolve and validate
CONNECTOR_DIR="${CONNECTOR_DIR%/}"
if [ ! -d "${CONNECTOR_DIR}" ]; then
    echo "Error: connector directory '${CONNECTOR_DIR}' does not exist." >&2
    exit 1
fi

# Infer CONNECTOR_TYPE from the top-level directory name
# e.g. external-import -> EXTERNAL_IMPORT
TOP_DIR="$(echo "${CONNECTOR_DIR}" | cut -d/ -f1)"
CONNECTOR_TYPE="$(echo "${TOP_DIR}" | tr '[:lower:]-' '[:upper:]_')"

CONNECTOR_NAME="$(basename "${CONNECTOR_DIR}")"
IMAGE="opencti/connector-${CONNECTOR_NAME}:${VERSION}-ubi9"
ENV_FILE="${CONNECTOR_DIR}/.build.env"


# Build argument list
set -- -f "${SCRIPT_DIR}/Dockerfile_ubi9"
set -- "$@" --build-arg "CONNECTOR_TYPE=${CONNECTOR_TYPE}"

# Append connector-specific overrides from env file as --build-arg flags
if [ -f "${ENV_FILE}" ]; then
    eval set -- '"$@"' $(sed '/^$/d; /^#/d; s/^/--build-arg /' "${ENV_FILE}")
fi

set -- "$@" -t "${IMAGE}"
set -- "$@" "${CONNECTOR_DIR}"

if command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
else
    RUNTIME=docker
fi

${RUNTIME} build "$@"

if [ "${PUSH}" = true ]; then
    echo "Pushing ${IMAGE}..."
    ${RUNTIME} push "${IMAGE}"
fi
