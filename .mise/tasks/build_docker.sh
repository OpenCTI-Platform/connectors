#!/usr/bin/env bash
#MISE description="Build Connector docker image then the Global Manifest and restart OpenCTI"
#MISE alias=["build", "b"]
#MISE dir="{{cwd}}"
#USAGE flag "--no-cache" help="Disable Docker layer caching"

set -euo pipefail

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/_helpers.sh"

# ---------------------------------------------------------------------------
# Load manifest & build
# ---------------------------------------------------------------------------
load_manifest

IMAGE_TAG="$(docker_image_tag)"

log_step "Building Docker image for connector"
log_info "  CONTAINER_IMAGE   = $CONTAINER_IMAGE"
log_info "  CONTAINER_VERSION = $CONTAINER_VERSION"
log_info "  IMAGE_TAG         = $IMAGE_TAG"

NO_CACHE_FLAG=""
[[ "${usage_no_cache:-}" == "true" ]] && NO_CACHE_FLAG="--no-cache"

if command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
else
    RUNTIME=docker
fi

$RUNTIME buildx build $NO_CACHE_FLAG -t "$IMAGE_TAG" .

log_info "✅ Docker image built successfully: $IMAGE_TAG"
