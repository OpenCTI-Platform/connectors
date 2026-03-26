#!/usr/bin/env bash
set -euo pipefail

remote="${1:-origin}"

candidates=()
while IFS= read -r line; do
  candidates+=("${line}")
done < <(
  {
    git for-each-ref --format='%(refname:short)' "refs/remotes/${remote}/master"
    git for-each-ref --format='%(refname:short)' "refs/remotes/${remote}/release/6.9.x"
    git for-each-ref --format='%(refname:short)' "refs/remotes/${remote}/lts/*"
  } | sed "s#^${remote}/##" | awk 'NF' | sort -u
)

if [[ "${#candidates[@]}" -eq 0 ]]; then
  echo "No candidate branch found on remote '${remote}'" >&2
  exit 1
fi

head_sha="$(git rev-parse HEAD)"

# 1) If HEAD is exactly at candidate branch tip, return it immediately.
for branch in "${candidates[@]}"; do
  branch_sha="$(git rev-parse "${remote}/${branch}" 2>/dev/null || true)"
  if [[ -n "${branch_sha}" && "${branch_sha}" == "${head_sha}" ]]; then
    echo "${branch}"
    exit 0
  fi
done

# 2) Prefer direct ancestry: candidate tip is ancestor of HEAD with shortest distance.
best_branch=""
best_distance=999999999
for branch in "${candidates[@]}"; do
  ref="${remote}/${branch}"
  if ! git merge-base --is-ancestor "${ref}" HEAD 2>/dev/null; then
    continue
  fi
  distance="$(git rev-list --count "${ref}..HEAD")"
  if (( distance < best_distance )); then
    best_branch="${branch}"
    best_distance="${distance}"
  fi
done
if [[ -n "${best_branch}" ]]; then
  echo "${best_branch}"
  exit 0
fi

# 3) Fallback: pick branch with nearest merge-base to HEAD.
for branch in "${candidates[@]}"; do
  ref="${remote}/${branch}"
  merge_base="$(git merge-base HEAD "${ref}" 2>/dev/null || true)"
  if [[ -z "${merge_base}" ]]; then
    continue
  fi
  distance="$(git rev-list --count "${merge_base}..HEAD")"
  if (( distance < best_distance )); then
    best_branch="${branch}"
    best_distance="${distance}"
  fi
done

if [[ -n "${best_branch}" ]]; then
  echo "${best_branch}"
  exit 0
fi

echo "No candidate branch found" >&2
exit 1
