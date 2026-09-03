#!/usr/bin/env bash
# Build (and optionally push) a connector image with docker buildx, retrying
# transient failures (e.g. registry 5xx/timeouts, rate limiting) with
# exponential backoff, honoring the registry's "retry-after" hint as a floor.
#
# The image push and the registry build-cache export are run as two separate
# buildx invocations. Bundling them in one invocation is fragile: if the cache
# export hits a transient registry error (e.g. ghcr.io "toomanyrequests" write
# rate limiting, which is common when many connectors build concurrently),
# BuildKit cancels the *entire* solve, including an image export that had
# already succeeded — turning a harmless cache-write hiccup into a full build
# failure. Since the build-cache export is only a CI speed optimization (not
# required to ship the connector image), its failures are retried but treated
# as non-fatal once the image itself has been pushed successfully.
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
#   CACHE_TO     - buildx --cache-to value (skipped when empty). Pushed in a
#                  separate, non-fatal retry loop after the image push succeeds.
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
INITIAL_DELAY="${INITIAL_DELAY:-60}"

METADATA_FILE="$(mktemp)"

# Assemble the shared buildx argument list (everything except cache-to, which
# is applied only to the separate cache-export attempt below).
base_args=(build "$CONTEXT" --file "$DOCKERFILE" --platform "$PLATFORMS")
base_args+=(--provenance "$PROVENANCE" --metadata-file "$METADATA_FILE")

if [ "$PULL" = "true" ]; then
  base_args+=(--pull)
fi
if [ "$PUSH" = "true" ]; then
  base_args+=(--push)
fi

while IFS= read -r tag; do
  [ -n "$tag" ] && base_args+=(--tag "$tag")
done <<< "$TAGS"

if [ -n "${BUILD_ARGS:-}" ]; then
  while IFS= read -r ba; do
    [ -n "$ba" ] && base_args+=(--build-arg "$ba")
  done <<< "$BUILD_ARGS"
fi

if [ -n "${LABELS:-}" ]; then
  while IFS= read -r label; do
    [ -n "$label" ] && base_args+=(--label "$label")
  done <<< "$LABELS"
fi

if [ -n "${CACHE_FROM:-}" ]; then
  base_args+=(--cache-from "$CACHE_FROM")
fi

# Extracts the largest "retry-after: <n>(ms|s)" hint from buildx output, in
# whole seconds (rounded up). Registries return this per-request, so under
# heavy matrix concurrency it's usually far smaller than our own backoff
# (e.g. "retry-after: 17ms" while 200 other jobs hammer the same quota) — it's
# only used as a floor, never to shrink the exponential backoff.
parse_retry_after_seconds() {
  local log_file="$1"
  awk '
    match($0, /retry-after: [0-9.]+(ms|s)/) {
      s = substr($0, RSTART, RLENGTH)
      sub(/retry-after: /, "", s)
      unit = (s ~ /ms$/) ? "ms" : "s"
      gsub(/[a-z]/, "", s)
      val = s + 0
      if (unit == "ms") val = val / 1000
      if (val > max) max = val
    }
    END { if (max > 0) printf "%d\n", (max == int(max)) ? max : int(max) + 1 }
  ' "$log_file"
}

# Runs `docker buildx "${@}"` with exponential backoff + jitter.
# Returns 1 after exhausting MAX_ATTEMPTS (caller decides fatal vs non-fatal).
run_with_retry() {
  local attempt=1
  local delay="$INITIAL_DELAY"
  local log_file
  log_file="$(mktemp)"
  while true; do
    echo "🐳 docker buildx (attempt ${attempt}/${MAX_ATTEMPTS}): $*"
    : > "$log_file"
    if docker buildx "$@" 2>&1 | tee "$log_file"; then
      rm -f "$log_file"
      return 0
    fi
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
      rm -f "$log_file"
      return 1
    fi
    # Wide, randomized jitter so many connectors building concurrently in the
    # same matrix don't retry in lockstep and re-collide on the same
    # registry rate-limit window.
    jitter=$((RANDOM % 30))
    sleep_for=$((delay + jitter))
    retry_after="$(parse_retry_after_seconds "$log_file")"
    if [ -n "$retry_after" ] && [ "$retry_after" -gt "$sleep_for" ]; then
      echo "⏱️  registry requested retry-after ${retry_after}s, honoring it"
      sleep_for="$((retry_after + jitter))"
    fi
    echo "⚠️  buildx attempt ${attempt} failed, retrying in ${sleep_for}s..."
    sleep "$sleep_for"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

# Step 1: build + push the actual image. Must succeed.
if ! run_with_retry "${base_args[@]}"; then
  echo "❌ buildx image push failed after ${MAX_ATTEMPTS} attempts"
  rm -f "$METADATA_FILE"
  exit 1
fi

if [ -n "${DIGEST_OUT:-}" ]; then
  DIGEST="$(jq -r '.["containerimage.digest"] // empty' "$METADATA_FILE")"
  echo "$DIGEST" > "$DIGEST_OUT"
  echo "📋 Digest: ${DIGEST:-(none)}"
fi

# Step 2: export the registry build cache, isolated from the image push so a
# transient registry write failure here can't discard the already-pushed
# image. Everything is already cached locally from step 1, so this is fast.
# Failure is non-fatal: it only slows down the *next* CI build.
if [ -n "${CACHE_TO:-}" ]; then
  cache_args=("${base_args[@]}" --cache-to "$CACHE_TO")
  if ! run_with_retry "${cache_args[@]}"; then
    echo "⚠️  buildx cache export failed after ${MAX_ATTEMPTS} attempts, continuing anyway (image was already pushed)"
  fi
fi

rm -f "$METADATA_FILE"
