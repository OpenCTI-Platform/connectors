#!/usr/bin/env bash
#MISE description="Push Connector docker image to local registry"
#MISE depends=["build_docker"]
#MISE alias=["push", "p"]
#MISE dir="{{cwd}}"

set -euo pipefail

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/_helpers.sh"

# ---------------------------------------------------------------------------
# Load manifest & push
# ---------------------------------------------------------------------------
load_manifest

IMAGE_TAG="$(docker_image_tag)"

log_step "Pushing Docker image to local registry"
log_info "  IMAGE_TAG = $IMAGE_TAG"

if command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
else
    RUNTIME=docker
fi

$RUNTIME push "$IMAGE_TAG"

log_info "✅ Docker image pushed successfully: $IMAGE_TAG"
