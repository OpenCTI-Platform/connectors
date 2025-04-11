#!/bin/bash
set -e

connector_dir=$1

venv_name=".temp_venv"

test_requirements_files=$(find $connector_dir -name "test-requirements.txt")

echo 'Found test-requirements.txt files:' "$test_requirements_files"

if [ -z "$test_requirements_files" ]; then
  echo "No test-requirements.txt file found in $connector_dir"
else
  if [ -d "$venv_name" ]; then
    echo 'Removing existing virtual environment'
    rm -rf "$venv_name"
  fi

  echo "Creating virtual environment for $connector_dir"
  python3 -m venv "$venv_name"
  source "$venv_name/bin/activate"

  pip install --upgrade pip
  pip install -r "$test_requirements_files"

  echo "Running tests for $connector_dir"
  pytest "$connector_dir/tests"

  deactivate
  rm -rf "$venv_name"
fi

