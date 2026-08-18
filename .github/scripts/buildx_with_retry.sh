#!/usr/bin/env bash
# Build (and optionally push) a connector image with docker buildx, retrying
# transient failures (e.g. registry 5xx/timeouts, rate limiting) with
# exponential backoff.
#
# Required environment variables:
#   CONTEXT      - Build context directory
#   DOCKERFILE   - Path to the Dockerfile
#   PLATFORMS    - Target platform(s), e.g. "linux/amd64"
#   TAGS         - Newline-separated list of image tags
#
# Optional environment variables:
#   PUSH         - "true" to push, anything else to build only (default: false)
#   PULL         - "true" to always pull base images (default: true)
#   BUILD_ARGS   - Newline-separated list of KEY=VALUE build args
#   LABELS       - Newline-separated list of KEY=VALUE OCI labels
#   CACHE_FROM   - buildx --cache-from value (skipped when empty)
#   CACHE_TO     - buildx --cache-to value (skipped when empty)
#   PROVENANCE   - buildx --provenance value (default: false, matches
#                  docker/build-push-action so per-arch images stay
#                  single-manifest for the imagetools merge)
#   DIGEST_OUT   - File path to write the resulting image digest to
#   MAX_ATTEMPTS - Maximum number of attempts (default: 5)
#   INITIAL_DELAY- Initial backoff delay in seconds (default: 15)
set -euo pipefail

: "${CONTEXT:?CONTEXT is required}"
: "${DOCKERFILE:?DOCKERFILE is required}"
: "${PLATFORMS:?PLATFORMS is required}"
: "${TAGS:?TAGS is required}"

PUSH="${PUSH:-false}"
PULL="${PULL:-true}"
PROVENANCE="${PROVENANCE:-false}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-5}"
INITIAL_DELAY="${INITIAL_DELAY:-15}"

METADATA_FILE="$(mktemp)"

# Assemble the buildx argument list.
args=(build "$CONTEXT" --file "$DOCKERFILE" --platform "$PLATFORMS")
args+=(--provenance "$PROVENANCE" --metadata-file "$METADATA_FILE")

if [ "$PULL" = "true" ]; then
  args+=(--pull)
fi
if [ "$PUSH" = "true" ]; then
  args+=(--push)
fi

while IFS= read -r tag; do
  [ -n "$tag" ] && args+=(--tag "$tag")
done <<< "$TAGS"

if [ -n "${BUILD_ARGS:-}" ]; then
  while IFS= read -r ba; do
    [ -n "$ba" ] && args+=(--build-arg "$ba")
  done <<< "$BUILD_ARGS"
fi

if [ -n "${LABELS:-}" ]; then
  while IFS= read -r label; do
    [ -n "$label" ] && args+=(--label "$label")
  done <<< "$LABELS"
fi

if [ -n "${CACHE_FROM:-}" ]; then
  args+=(--cache-from "$CACHE_FROM")
fi
if [ -n "${CACHE_TO:-}" ]; then
  args+=(--cache-to "$CACHE_TO")
fi

attempt=1
delay="$INITIAL_DELAY"
while true; do
  echo "🐳 docker buildx (attempt ${attempt}/${MAX_ATTEMPTS})"
  if docker buildx "${args[@]}"; then
    break
  fi
  if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
    echo "❌ buildx failed after ${attempt} attempts"
    rm -f "$METADATA_FILE"
    exit 1
  fi
  jitter=$((RANDOM % 5))
  sleep_for=$((delay + jitter))
  echo "⚠️  buildx attempt ${attempt} failed, retrying in ${sleep_for}s..."
  sleep "$sleep_for"
  attempt=$((attempt + 1))
  delay=$((delay * 2))
done

if [ -n "${DIGEST_OUT:-}" ]; then
  DIGEST="$(jq -r '.["containerimage.digest"] // empty' "$METADATA_FILE")"
  echo "$DIGEST" > "$DIGEST_OUT"
  echo "📋 Digest: ${DIGEST:-(none)}"
fi

rm -f "$METADATA_FILE"
