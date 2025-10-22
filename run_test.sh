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

for requirements_file in $test_requirements_files
do
  project="$(dirname "$requirements_file")"

  if [ "$CIRCLE_BRANCH" = "feat/4927-circleci-execute-the-tests-depending-on-the-context" ]; then
    echo "🔄 On master branch, running all tests for: " "$project"
  elif [ -z $(git diff $(git merge-base master HEAD) HEAD "$project/..") ] ; then
    echo "☑️ Nothing has changed in: " "$project"
    continue
  else
    echo "🔄 Changes detected in: " "$project"
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


  echo 'Running tests'
  python -m pytest "$project" --junitxml="$OUT_DIR/junit.xml" -q -rA  # exit non zero if no test run

  echo 'Removing virtual environment'
  deactivate
  rm -rf "$venv_name"
done


