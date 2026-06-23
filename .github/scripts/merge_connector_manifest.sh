#!/usr/bin/env bash
# Merge multi-arch manifest for a single connector using digests.
# FIPS images are amd64-only and pushed directly — no merge needed.
#
# Required environment variables:
#   CONNECTOR_NAME     - Connector name (e.g. "mitre")
#   IMAGE_TAGS         - Comma-separated image tags (e.g. "rolling" or "7.260529.0,latest")
#   DIGESTS_DIR_AMD64  - Directory containing the amd64 digest file
#   DIGESTS_DIR_ARM64  - Directory containing the arm64 digest file
#   DRY_RUN            - "true" to use --dry-run (validate without pushing)
set -euo pipefail

REPO="opencti"
DRY_RUN_FLAG=""
if [ "${DRY_RUN:-false}" = "true" ]; then
  DRY_RUN_FLAG="--dry-run"
  echo "⚠️  Dry-run mode — manifests will be validated but not pushed"
fi

# Read digests
AMD64_DIGEST=$(cat "${DIGESTS_DIR_AMD64}/${CONNECTOR_NAME}")
ARM64_DIGEST=$(cat "${DIGESTS_DIR_ARM64}/${CONNECTOR_NAME}")

echo "🔗 Merging $CONNECTOR_NAME"
echo "  amd64: $AMD64_DIGEST"
echo "  arm64: $ARM64_DIGEST"

DH_IMAGE="${REPO}/connector-${CONNECTOR_NAME}"
GHCR_IMAGE="ghcr.io/opencti-platform/${REPO}/connector-${CONNECTOR_NAME}"

IFS=',' read -ra TAG_ARRAY <<< "$IMAGE_TAGS"
for tag in "${TAG_ARRAY[@]}"; do
  tag=$(echo "$tag" | xargs)

  docker buildx imagetools create $DRY_RUN_FLAG -t "${DH_IMAGE}:${tag}" \
    "${DH_IMAGE}@${AMD64_DIGEST}" \
    "${DH_IMAGE}@${ARM64_DIGEST}"

  docker buildx imagetools create $DRY_RUN_FLAG -t "${GHCR_IMAGE}:${tag}" \
    "${GHCR_IMAGE}@${AMD64_DIGEST}" \
    "${GHCR_IMAGE}@${ARM64_DIGEST}"
done
echo "✅ Merged $CONNECTOR_NAME"
