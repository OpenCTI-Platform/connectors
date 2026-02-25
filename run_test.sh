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
  project_has_sdk_dependency=$(grep -rl "connectors-sdk" "$project/.." || true)

  if [ "$CIRCLE_BRANCH" = "master" ]; then
    echo "🔄 On master branch, running all tests for: " "$project"
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

  echo 'Running tests pipeline for project' "$project"

  # Per-connector outputs
  OUT_DIR="test_outputs/$(echo "$project" | tr '/ ' '__')"
  mkdir -p "$OUT_DIR"

  echo 'Creating isolated virtual environment'
  python -m venv "$venv_name"
  if [ -f "$venv_name/bin/activate" ]; then
    source "$venv_name/bin/activate"  # Linux/MacOS
  elif [ -f "$venv_name/Scripts/activate" ]; then
    source "$venv_name/Scripts/activate"  # Windows
  fi

  echo 'Installing requirements'
  python -m pip install -q -r "$requirements_file"

  python -m pip freeze | grep "connectors-sdk\|pycti" || true

  if [ -n "$project_has_sdk_dependency" ] ; then
      echo 'Installing connectors-sdk local version'
      python -m pip uninstall -y connectors-sdk
      python -m pip install -q ./connectors-sdk
  fi

  python -m pip freeze | grep "connectors-sdk\|pycti" || true

  echo 'Installing latest version of pycti'
  python -m pip uninstall -y pycti
  python -m pip install -q git+https://github.com/OpenCTI-Platform/opencti.git@master#subdirectory=client-python
  python -m pip freeze | grep "connectors-sdk\|pycti" || true

  python -m pip check || exit 1  # exit if dependencies are broken

  echo 'Running tests'
  python -m pytest "$project" --junitxml="$OUT_DIR/junit.xml" -q -rA  # exit non zero if no test run

  echo 'Removing virtual environment'
  deactivate
  rm -rf "$venv_name"
done


