#!/bin/bash

set -e  # exit on error

venv_name=".temp_venv"

# virtual environment will not be cleaned up if script is interrupted
if [ -d "$venv_name" ]; then
  echo 'Removing virtual environment'
  rm -rf "$venv_name"
fi

if (( $# )); then
  test_requirements_files="$@"
  echo 'Using provided test-requirements.txt files:' "$test_requirements_files"
else
  test_requirements_files=$(find . -name "test-requirements.txt")
  echo 'Found test-requirements.txt files:' "$test_requirements_files"
fi

base_commit=$(git merge-base origin/master HEAD)
changes_outside_of_connectors_scope=$(git diff --name-only "$base_commit" HEAD -- \
  ':!connectors-sdk/**' \
  ':!external-import/**' \
  ':!internal-enrichment/**' \
  ':!internal-export-file/**' \
  ':!internal-import-file/**' \
  ':!stream/**'
)
sdk_has_change=$(git diff "$base_commit" HEAD "connectors-sdk")
echo 'connectors-sdk has changes:' "$sdk_has_change"

for requirements_file in $test_requirements_files
do
  project="$(dirname "$requirements_file")"
  project_has_changed=$(git diff "$base_commit" HEAD "$project/..")
  dependency_scope="$project/.."
  if [ "$project" = "tests" ]; then
    dependency_scope="$project"
  fi
  project_has_sdk_dependency=$(find "$dependency_scope" \
    \( -name "requirements.txt" -o -name "pyproject.toml" \) \
    -type f -exec grep -Il "connectors-sdk" {} + 2>/dev/null || true)

  if [ -n "$project_has_sdk_dependency" ] ; then
    echo 'Rewriting connectors-sdk dependencies to the local checkout for this test run'
    python3 - "$dependency_scope" "$(pwd)/connectors-sdk" <<'PY'
import pathlib
import re
import sys

scope = pathlib.Path(sys.argv[1])
local_sdk = pathlib.Path(sys.argv[2]).resolve().as_uri()
replacement = f"connectors-sdk @ {local_sdk}"
pattern = re.compile(
    r"connectors-sdk\s*@\s*git\+https://github\.com/OpenCTI-Platform/connectors\.git@[^#\s\"']+#subdirectory=connectors-sdk"
)

for path in scope.rglob("*"):
    if path.name not in {"requirements.txt", "pyproject.toml"}:
        continue
    original = path.read_text(encoding="utf-8")
    updated = pattern.sub(replacement, original)
    if updated != original:
        path.write_text(updated, encoding="utf-8")
PY
  fi

  project_pins_pycti=$(find "$dependency_scope" \
    \( -name "requirements.txt" -o -name "pyproject.toml" \) \
    -type f -exec grep -IlE 'pycti(==| @ )' {} + 2>/dev/null || true)

  if [ "$CIRCLE_BRANCH" = "${RELEASE_REF:-"master"}" ]; then
    echo "🔄 On ${RELEASE_REF:-"master"} branch, running all tests for: " "$project"
  elif [ -n "$changes_outside_of_connectors_scope" ] ; then
    echo "🔄 Changes detected outside of connectors scope - running all tests for: " "$project"
  elif [ -n "$sdk_has_change" ] && [ -n "$project_has_sdk_dependency" ] ; then
    echo "🔄 connectors-sdk changes affect: " "$project" "- running the tests"
  elif [ -n "$project_has_changed" ] ; then
    echo "🔄 Changes detected in: " "$project"
  else
    echo "☑️ Nothing has changed in: " "$project"
    continue
  fi

  echo 'Running tests uv pipeline for project' "$project"

  # Per-connector outputs
  OUT_DIR="test_outputs/$(echo "$project" | tr '/ ' '__')"
  mkdir -p "$OUT_DIR"

  echo 'Creating isolated virtual environment'
  uv venv -p 3.12 "$venv_name"
  if [ -f "$venv_name/bin/activate" ]; then
    source "$venv_name/bin/activate"  # Linux/MacOS
  elif [ -f "$venv_name/Scripts/activate" ]; then
    source "$venv_name/Scripts/activate"  # Windows
  fi

  echo 'Installing requirements'
  uv pip install -q -r "$requirements_file"

  if uv pip show pytest-cov >/dev/null 2>&1; then
    pytest_cov_installed_by_requirements="true"
    echo 'pytest-cov is provided by test requirements'
  else
    pytest_cov_installed_by_requirements="false"
    echo 'pytest-cov is not provided by test requirements'
  fi

  if [ -n "$project_has_sdk_dependency" ] ; then
      echo 'Installing connectors-sdk local version'
      uv pip uninstall connectors-sdk
      uv pip install -q ./connectors-sdk
  fi

  if [ -n "$project_has_sdk_dependency" ] || [ -n "$project_pins_pycti" ] ; then
    echo 'Keeping pycti version resolved by project requirements'
  else
    echo 'Installing latest version of pycti'
    uv pip uninstall pycti
    REF="${CIRCLE_TAG:-${RELEASE_REF:-"master"}}"
    uv pip install -q git+https://github.com/OpenCTI-Platform/opencti.git@"$REF"#subdirectory=client-python
  fi
  uv pip freeze | grep "connectors-sdk\|pycti" || true

  uv pip check || exit 1  # exit if dependencies are broken

  echo 'Running tests'
  if [ "$pytest_cov_installed_by_requirements" = "true" ]; then
    echo 'Using project pytest configuration'
    # --cov is not needed because already configured as addopts in pyproject.toml
    # --cov-append is needed to merge coverage results from multiple test runs
    python -m pytest "$project" --cov-append --cov-report=xml \
      --junitxml="$OUT_DIR/junit.xml" -q -rA  # exit non zero if no test run
  else
    echo 'Installing pytest-cov and using explicit coverage arguments'
    uv pip install -q pytest-cov
    python -m pytest "$project" --cov --cov-append \
      --cov-report=xml --junitxml="$OUT_DIR/junit.xml" -q -rA  # exit non zero if no test run
  fi

  echo 'Removing virtual environment'
  deactivate
  rm -rf "$venv_name"
done
