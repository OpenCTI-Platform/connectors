#!/usr/bin/env bash
# Point the connectors-sdk git references of the current branch at another ref.
#
# Why: connectors declare their SDK as
#   connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk
# On a branch cut from master (typically lts/<version>) that reference must point at the
# branch itself. Left on master, dependency resolution breaks as soon as master moves to a
# newer pycti than the one pinned by the branch ("connectors-sdk depends on pycti==<master>
# and you require pycti==<lts>"), and every connector test job fails before running a test.
#
# Run it once, on the new branch, right after cutting it, then commit the result:
#   shared/tools/ci/align-sdk-refs.sh lts/7.260930.0            # dry run, lists the files
#   shared/tools/ci/align-sdk-refs.sh lts/7.260930.0 --apply    # rewrites them
#
# Usage: align-sdk-refs.sh <ref> [--from <ref>] [--apply]
#   <ref>          Ref connectors-sdk must point at (e.g. lts/7.260930.0).
#   --from <ref>   Ref to replace (default: master).
#   --apply        Write the changes. Without it nothing is modified (dry run).
#
# Only tracked requirements*.txt and pyproject.toml files are considered. Generated
# *.egg-info metadata is left alone. Running it again with the same ref changes nothing.
set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^#   --apply/p' "$0" | sed 's/^# \{0,1\}//' >&2
}

die() {
  echo "Error: $*" >&2
  exit 1
}

for cmd in git perl grep; do
  command -v "$cmd" > /dev/null 2>&1 || die "'$cmd' is required but was not found in PATH. Install it and retry."
done

to_ref=""
from_ref="master"
apply="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      apply="true"
      shift
      ;;
    --from)
      [[ $# -ge 2 ]] || { usage; die "--from needs a value."; }
      from_ref="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      usage
      die "unknown option '$1'."
      ;;
    *)
      [[ -z "$to_ref" ]] || { usage; die "only one target ref is accepted (got '$to_ref' and '$1')."; }
      to_ref="$1"
      shift
      ;;
  esac
done

[[ -n "$to_ref" ]] || { usage; die "missing target ref."; }

ref_pattern='^[A-Za-z0-9._/-]+$'
[[ "$to_ref" =~ $ref_pattern ]] || die "invalid target ref '$to_ref'."
[[ "$from_ref" =~ $ref_pattern ]] || die "invalid --from ref '$from_ref'."
[[ "$to_ref" != "$from_ref" ]] || die "the target ref and --from are the same ('$to_ref'), nothing to do."

repo_root="$(git rev-parse --show-toplevel 2> /dev/null)" || die "not inside a git repository."
cd "$repo_root"

suffix="#subdirectory=connectors-sdk"
old_ref="connectors.git@${from_ref}${suffix}"
new_ref="connectors.git@${to_ref}${suffix}"

matches=()
while IFS= read -r -d '' file; do
  [[ "$file" == *.egg-info/* ]] && continue
  if grep -qF -- "$old_ref" "$file"; then
    matches+=("$file")
  fi
done < <(git ls-files -z -- '*requirements*.txt' '*pyproject.toml')

if [[ "${#matches[@]}" -eq 0 ]]; then
  echo "Nothing to align: no tracked file points connectors-sdk at '${from_ref}'."
  exit 0
fi

if [[ "$apply" != "true" ]]; then
  printf '%s\n' "${matches[@]}"
  echo
  echo "Dry run: ${#matches[@]} file(s) would point connectors-sdk at '${to_ref}' instead of '${from_ref}'."
  echo "Re-run with --apply to write the changes."
  exit 0
fi

for file in "${matches[@]}"; do
  OLD="$old_ref" NEW="$new_ref" perl -pi -e 's/\Q$ENV{OLD}\E/$ENV{NEW}/g' -- "$file"
done

remaining=0
for file in "${matches[@]}"; do
  if grep -qF -- "$old_ref" "$file"; then
    echo "Warning: '$file' still points at '${from_ref}'." >&2
    remaining=$((remaining + 1))
  fi
done

echo "Updated ${#matches[@]} file(s): connectors-sdk now points at '${to_ref}'."
[[ "$remaining" -eq 0 ]] || die "${remaining} file(s) were not fully rewritten, check the warnings above."
