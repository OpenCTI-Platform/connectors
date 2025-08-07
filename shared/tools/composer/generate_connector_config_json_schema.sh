#!/bin/bash

set -euo pipefail  # exit on error

CONNECTOR_METADATA_DIRECTORY="__metadata__"
CONNECTOR_MANIFEST_FILENAME="connector_manifest.json"
VENV_NAME=".temp_venv"

find_requirements_txt() {
  # Method to find the highest requirements.txt in connector's tree

  # find: find all requirements.txt recursively
  # awk: count path length
  # sort: sort by path length
  # head: take the first file
  # cut: get file path only
  find "$1" -type f -name "requirements.txt" \
    | awk -F/ '{print NF, $0}' \
    | sort -n \
    | head -n1 \
    | cut -d' ' -f2-
}

activate_venv() {
    # Method to activate isolate venv

    # Install dependencies
    requirements_file=$(find_requirements_txt "$1")

    # Create isolated virtual environment in connector path
    python -m venv "$1/$VENV_NAME"

    # Activate virtual environment according to OS
    if [ -f "$1/$VENV_NAME/bin/activate" ]; then
      source "$1/$VENV_NAME/bin/activate"  # Linux/MacOS
    elif [ -f "$1/$VENV_NAME/Scripts/activate" ]; then
      source "$1/$VENV_NAME/Scripts/activate"  # Windows
    fi

    echo '> Installing requirements in: ' "$1"

    # -qq: Hides both informational and warning messages, showing only errors.
    python -m pip install -qq -r "$requirements_file"

    # Check if venv is well created
    venv_exists=$(find "$1" -name ".temp_venv")

    if [ -d "$venv_exists" ]; then
      echo "✅ Requirements installed for: " "$1"
    else
      echo "❌ Requirements not installed for: " "$1"
    fi
}

deactivate_venv() {
    # Method to deactivate venv and remove the folder
    echo "> Cleaning up environment..."
    deactivate
    rm -rf "$1"
}

# Find all parents directory of connector with config loader
# printf action with the %h format specifier, which prints the directory part (parent directory) of the file path
connector_directories_path=$(find . -type d -name "$CONNECTOR_METADATA_DIRECTORY" -printf '%h\n')

# ! This script should generate connector_config_schema.json for one connector ONLY
# ! Looping over all connectors should be done in a dedicated CI job
# Loop in each connector directory with infos
for connector_directory_path in $connector_directories_path
do
  if [ -d "$connector_directory_path" ]; then
    echo "> Looking for a config loader in " "$connector_directory_path"
    requirements_file=$(find_requirements_txt "$connector_directory_path")
    echo "Found requirements.txt: " "$requirements_file"
    if [ -f "$requirements_file" ] && grep -q "pydantic-settings" "$requirements_file"; then
      (
        activate_venv "$connector_directory_path"
        generator_path=$(find . -name "generate_connector_config_json_schema.py.sample")
        cp "$generator_path" "$connector_directory_path/generate_connector_config_json_schema_tmp.py"
        python "$connector_directory_path/generate_connector_config_json_schema_tmp.py"
        rm "$connector_directory_path/generate_connector_config_json_schema_tmp.py"
        deactivate_venv "$connector_directory_path/$VENV_NAME"
      ) &
    fi
  fi
done
wait