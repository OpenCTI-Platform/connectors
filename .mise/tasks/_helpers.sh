#!/usr/bin/env bash
# _helpers.sh — Shared utilities for mise tasks
#
# Usage: source this file from any task script via:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$SCRIPT_DIR/_helpers.sh"
#
# This file intentionally has NO #MISE directives so mise won't register it
# as a task.

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_info()  { printf "${GREEN}%s${RESET}\n" "$*"; }
log_warn()  { printf "${YELLOW}%s${RESET}\n" "$*"; }
log_error() { printf "${RED}%s${RESET}\n" "$*" >&2; }
log_step()  { printf "${CYAN}> %s${RESET}\n" "$*"; }

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
require_cmd() {
    # Verify that a command is available on PATH.
    #   $1 — command name
    #   $2 — (optional) install hint shown on failure
    local cmd="$1"
    local install_hint="${2:-}"

    if ! command -v "$cmd" &>/dev/null; then
        if [[ -n "$install_hint" ]]; then
            log_error "Error: $cmd is required. Install with: $install_hint"
        else
            log_error "Error: $cmd is required but was not found on PATH."
        fi
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
find_shallowest_file() {
    # Find the shallowest (closest to root) file matching a given name
    # inside a directory tree.
    #   $1 — base directory to search
    #   $2 — filename to look for (e.g. "requirements.txt")
    find "$1" -type f -name "$2" \
        | awk -F/ '{print NF, $0}' \
        | sort -n \
        | head -n1 \
        | cut -d' ' -f2-
}

# ---------------------------------------------------------------------------
# Connector manifest helpers
# ---------------------------------------------------------------------------
load_manifest() {
    # Parse the connector manifest and export CONTAINER_VERSION and
    # CONTAINER_IMAGE.  Exits with an error if anything is missing.
    #   $1 — (optional) path to manifest; defaults to
    #         $PWD/__metadata__/connector_manifest.json
    local manifest_path="${1:-${PWD}/__metadata__/connector_manifest.json}"

    if [[ ! -f "$manifest_path" ]]; then
        log_error "Error: manifest not found at $manifest_path"
        exit 1
    fi

    require_cmd jq "brew install jq"

    CONTAINER_VERSION=$(jq -r '.container_version // empty' "$manifest_path")
    CONTAINER_IMAGE=$(jq -r '.container_image // empty' "$manifest_path")

    if [[ -z "${CONTAINER_VERSION:-}" ]]; then
        log_error "Error: 'container_version' is missing or empty in $manifest_path"
        exit 1
    fi
    if [[ -z "${CONTAINER_IMAGE:-}" ]]; then
        log_error "Error: 'container_image' is missing or empty in $manifest_path"
        exit 1
    fi

    export CONTAINER_VERSION CONTAINER_IMAGE
}

docker_image_tag() {
    # Print the fully-qualified local-registry image tag.
    # Requires CONTAINER_IMAGE and CONTAINER_VERSION to be set (via
    # load_manifest).
    local registry="${DOCKER_REGISTRY:-registry:5000}"
    printf "%s/%s:%s" "$registry" "$CONTAINER_IMAGE" "$CONTAINER_VERSION"
}
