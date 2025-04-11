#!/bin/bash
set -e

connector_dir=$1
cd connector_dir
venv_name=".temp_venv"

if [ -d "$venv_name" ]; then
  echo 'Removing existing virtual environment'
  rm -rf "$venv_name"
fi

echo "Creating virtual environment for $connector_dir"
python3 -m venv "$venv_name"
source "$venv_name/bin/activate"

pip install --upgrade pip
pip install -r "$connector_dir/test-requirements.txt"

echo "Running tests for $connector_dir"
pytest "$connector_dir/tests"

deactivate
rm -rf "$venv_name"