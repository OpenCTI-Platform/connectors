#!/usr/bin/env bash
# Prints "true" when the branch has moved past EXPECTED_SHA in a way that makes
# this run stale, "false" when it is still safe to commit on top.
#
# Manifest bot commits are ignored, otherwise a newer run would be discarded
# just because an overlapping run already pushed its manifest. Any other newer
# commit has its own run, which regenerates everything. A tip that no longer
# contains EXPECTED_SHA (force-push) counts as newer.
#
# Required environment variables:
#   GH_TOKEN, REPO (owner/name), BRANCH, EXPECTED_SHA
set -euo pipefail

: "${REPO:?}" "${BRANCH:?}" "${EXPECTED_SHA:?}"
BOT_PREFIX="chore(manifest): build and update manifest"

err="$(mktemp)"
if ! resp=$(gh api "repos/${REPO}/compare/${EXPECTED_SHA}...${BRANCH}" 2>"$err"); then
  if grep -qiE "not found|404|No common ancestor" "$err"; then
    echo "::warning::${EXPECTED_SHA} is no longer reachable from '${BRANCH}'." >&2
    echo true
    exit 0
  fi
  cat "$err" >&2
  exit 1
fi

status=$(jq -r '.status' <<< "$resp")
case "$status" in
  identical)
    echo false
    ;;
  ahead)
    total=$(jq -r '.total_commits' <<< "$resp")
    listed=$(jq -r '.commits | length' <<< "$resp")
    other=$(jq -r --arg p "$BOT_PREFIX" \
      '[.commits[] | select(.commit.message | startswith($p) | not)] | length' <<< "$resp")
    # The API lists at most 250 commits; an unlisted tail is assumed real work.
    if [ "$other" -gt 0 ] || [ "$total" -gt "$listed" ]; then
      echo "::warning::Branch '${BRANCH}' has newer non-manifest commits after ${EXPECTED_SHA}." >&2
      echo true
    else
      echo false
    fi
    ;;
  *)
    echo "::warning::Branch '${BRANCH}' is ${status} relative to ${EXPECTED_SHA}." >&2
    echo true
    ;;
esac
