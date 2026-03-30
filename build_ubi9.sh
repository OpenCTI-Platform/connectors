#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    echo "Usage: $0 <connector-dir> <version>" >&2
    echo "  connector-dir  Path to the connector (e.g. external-import/crowdstrike)" >&2
    echo "  version        Image version tag" >&2
    exit 1
}

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

# Defaults for optional build args
EXTRA_PACKAGES=""
CONNECTOR_CMD=""
CONNECTOR_WORKDIR=""
POST_INSTALL=""

# Load connector-specific overrides if present
ENV_FILE="${CONNECTOR_DIR}/.build.env"
if [ -f "${ENV_FILE}" ]; then
    . "${ENV_FILE}"
fi

# Build argument list using positional params (handles spaces correctly)
set -- -f "${SCRIPT_DIR}/Dockerfile_ubi9"
set -- "$@" --build-arg "CONNECTOR_TYPE=${CONNECTOR_TYPE}"
[ -n "${EXTRA_PACKAGES}" ]    && set -- "$@" --build-arg "EXTRA_PACKAGES=${EXTRA_PACKAGES}"
[ -n "${CONNECTOR_CMD}" ]     && set -- "$@" --build-arg "CONNECTOR_CMD=${CONNECTOR_CMD}"
[ -n "${CONNECTOR_WORKDIR}" ] && set -- "$@" --build-arg "CONNECTOR_WORKDIR=${CONNECTOR_WORKDIR}"
[ -n "${POST_INSTALL}" ]      && set -- "$@" --build-arg "POST_INSTALL=${POST_INSTALL}"
set -- "$@" -t "opencti/connector-${CONNECTOR_NAME}:${VERSION}-ubi9"
set -- "$@" "${CONNECTOR_DIR}"

if command -v podman >/dev/null 2>&1; then
    MSYS_NO_PATHCONV=1 podman build "$@"
else
    MSYS_NO_PATHCONV=1 docker build "$@"
fi
