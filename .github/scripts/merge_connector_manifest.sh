#!/usr/bin/env bash
# Publish a connector's moving image tags from this run's digests:
#   - a multi-arch index (amd64 + arm64), and
#   - the "<tag>-fips" image, when a FIPS digest is present (amd64 only).
#
# Required environment variables:
#   CONNECTOR_NAME     - Connector name (e.g. "mitre")
#   IMAGE_TAGS         - Comma-separated image tags (e.g. "rolling" or "7.260529.0,latest")
#   DIGESTS_DIR_AMD64  - Directory with the amd64 digest file (and optional "<name>-fips")
#   DIGESTS_DIR_ARM64  - Directory with the arm64 digest file
#   GITHUB_SHA         - Commit being published (set by GitHub Actions)
#
# Optional environment variables:
#   DRY_RUN            - "true" to use --dry-run (validate without pushing)
#   GUARD_STALE        - "true" to never move a tag backwards (see below)
#   VERIFY_ROUNDS      - Post-push verification rounds (default: 3)
#   VERIFY_INTERVAL    - Seconds between verification rounds (default: 10)
#   MAX_ATTEMPTS       - Attempts per registry call (default: 5)
#   INITIAL_DELAY      - Initial retry backoff in seconds, doubled each attempt (default: 5)
#   DH_IMAGE, GHCR_IMAGE - Override the target image names (tests)
#
# Tag ordering: overlapping runs can reach this step out of commit order, so an
# older commit could overwrite a tag already published from a newer one.
# Concurrency groups can't prevent that (they order by job arrival and may drop
# jobs), so it is enforced against the registry instead:
#   1. Each image records its source commit: an annotation on the index, a
#      label on the FIPS image.
#   2. Before overwriting a tag, skip the push if the commit it was built from
#      is a strict descendant of ours.
#   3. Registries have no compare-and-swap, so after pushing we re-read each
#      tag for a few rounds and push again if an older commit overwrote it.
#
# Registry calls are retried with backoff; permanent errors (not found, denied,
# unauthorized) fail immediately.
#
# The guard fails open: no recorded commit, an unknown commit or a registry
# error means "push". Diverged commits (e.g. release/* vs lts/*) are pushed too.
set -euo pipefail

for cmd in docker jq git; do
  if ! command -v "$cmd" > /dev/null; then
    echo "❌ Required command not found: ${cmd}. Install it on the runner." >&2
    exit 1
  fi
done

REPO="opencti"
DRY_RUN_FLAG=""
if [ "${DRY_RUN:-false}" = "true" ]; then
  DRY_RUN_FLAG="--dry-run"
  echo "⚠️  Dry-run mode — manifests will be validated but not pushed"
fi

GUARD_STALE="${GUARD_STALE:-false}"
VERIFY_ROUNDS="${VERIFY_ROUNDS:-3}"
VERIFY_INTERVAL="${VERIFY_INTERVAL:-10}"
SHA_KEY="io.opencti.build.sha"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-5}"
INITIAL_DELAY="${INITIAL_DELAY:-5}"
# Errors a retry can't fix. "failed to authorize ... oauth token" (token
# endpoint outage) is transient, so it deliberately doesn't match.
PERMANENT_ERRORS='MANIFEST_UNKNOWN|manifest unknown|not found|denied|unauthorized|invalid reference|no such'

# retry <command...>: run with exponential backoff + jitter. Stdout passes
# through, stderr is replayed after each attempt. Returns the last exit status
# when attempts run out or the error is permanent.
retry() {
  local attempt=1 delay="$INITIAL_DELAY" rc log sleep_for
  log=$(mktemp)
  while true; do
    rc=0
    "$@" 2>"$log" || rc=$?
    cat "$log" >&2
    if [ "$rc" -eq 0 ]; then
      rm -f "$log"
      return 0
    fi
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ] || grep -qiE "$PERMANENT_ERRORS" "$log"; then
      rm -f "$log"
      return "$rc"
    fi
    sleep_for=$((delay + RANDOM % 5))
    echo "⚠️  attempt ${attempt}/${MAX_ATTEMPTS} failed (exit ${rc}), retrying in ${sleep_for}s: $*" >&2
    sleep "$sleep_for"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

# Read digests
AMD64_DIGEST=$(cat "${DIGESTS_DIR_AMD64}/${CONNECTOR_NAME}")
ARM64_DIGEST=$(cat "${DIGESTS_DIR_ARM64}/${CONNECTOR_NAME}")
FIPS_DIGEST=""
if [ -f "${DIGESTS_DIR_AMD64}/${CONNECTOR_NAME}-fips" ]; then
  FIPS_DIGEST=$(cat "${DIGESTS_DIR_AMD64}/${CONNECTOR_NAME}-fips")
fi

echo "🔗 Merging $CONNECTOR_NAME"
echo "  amd64: $AMD64_DIGEST"
echo "  arm64: $ARM64_DIGEST"
[ -n "$FIPS_DIGEST" ] && echo "  fips:  $FIPS_DIGEST"

DH_IMAGE="${DH_IMAGE:-${REPO}/connector-${CONNECTOR_NAME}}"
GHCR_IMAGE="${GHCR_IMAGE:-ghcr.io/opencti-platform/${REPO}/connector-${CONNECTOR_NAME}}"

# Prints the commit the image at $1 was built from; empty when unknown.
published_sha() {
  local ref="$1" sha="" raw="" img=""
  # Multi-arch index: annotation written by publish_target.
  raw=$(retry docker buildx imagetools inspect --raw "$ref") || raw=""
  if [ -n "$raw" ]; then
    sha=$(jq -r --arg k "$SHA_KEY" '.annotations[$k] // empty' <<< "$raw" 2>/dev/null) || sha=""
  fi
  if [ -z "$sha" ] && [ -n "$raw" ]; then
    # Single-arch image (FIPS): label baked into the image config.
    img=$(retry docker buildx imagetools inspect --format '{{json .Image}}' "$ref") || img=""
    sha=$(jq -r --arg k "$SHA_KEY" '.config.Labels[$k] // empty' <<< "$img" 2>/dev/null) || sha=""
  fi
  printf '%s' "$sha"
}

# Prints how the published commit $1 relates to GITHUB_SHA:
#   newer    - strict descendant of ours (never overwrite)
#   older    - strict ancestor of ours
#   other    - same, unknown, or diverged
relation() {
  local published="$1"
  if [ -z "$published" ] || [ "$published" = "$GITHUB_SHA" ] \
    || ! git cat-file -e "${published}^{commit}" 2>/dev/null; then
    echo other
  elif git merge-base --is-ancestor "$GITHUB_SHA" "$published"; then
    echo newer
  elif git merge-base --is-ancestor "$published" "$GITHUB_SHA"; then
    echo older
  else
    echo other
  fi
}

# publish_target <image> <tag> <index|single>
publish_target() {
  local image="$1" tag="$2" kind="$3"
  if [ "$kind" = "index" ]; then
    # shellcheck disable=SC2086
    retry docker buildx imagetools create $DRY_RUN_FLAG -t "${image}:${tag}" \
      --annotation "index:${SHA_KEY}=${GITHUB_SHA}" \
      "${image}@${AMD64_DIGEST}" \
      "${image}@${ARM64_DIGEST}"
  else
    # shellcheck disable=SC2086
    retry docker buildx imagetools create $DRY_RUN_FLAG -t "${image}:${tag}" \
      "${image}@${FIPS_DIGEST}"
  fi
}

TARGETS=()
IFS=',' read -ra TAG_ARRAY <<< "$IMAGE_TAGS"
for tag in "${TAG_ARRAY[@]}"; do
  tag=$(echo "$tag" | xargs)
  for image in "$DH_IMAGE" "$GHCR_IMAGE"; do
    TARGETS+=("${image}|${tag}|index")
    if [ -n "$FIPS_DIGEST" ]; then
      TARGETS+=("${image}|${tag}-fips|single")
    fi
  done
done

PUBLISHED=0
for target in "${TARGETS[@]}"; do
  IFS='|' read -r image tag kind <<< "$target"
  if [ "$GUARD_STALE" = "true" ] && [ "$(relation "$(published_sha "${image}:${tag}")")" = "newer" ]; then
    echo "⏭️  ${image}:${tag} already built from a newer commit — not overwriting with ${GITHUB_SHA}"
    continue
  fi
  publish_target "$image" "$tag" "$kind"
  PUBLISHED=$((PUBLISHED + 1))
done

# Step 3: catch an older run that wrote the tag after us. Only needed if we pushed.
if [ "$GUARD_STALE" = "true" ] && [ -z "$DRY_RUN_FLAG" ] && [ "$PUBLISHED" -gt 0 ]; then
  for ((round = 1; round <= VERIFY_ROUNDS; round++)); do
    sleep "$VERIFY_INTERVAL"
    for target in "${TARGETS[@]}"; do
      IFS='|' read -r image tag kind <<< "$target"
      if [ "$(relation "$(published_sha "${image}:${tag}")")" = "older" ]; then
        echo "↩️  ${image}:${tag} was overwritten by an older commit — restoring ${GITHUB_SHA}"
        publish_target "$image" "$tag" "$kind"
      fi
    done
  done
fi

echo "✅ Merged $CONNECTOR_NAME"
