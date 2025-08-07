#!/bin/bash

set -euo pipefail  # exit on error

CONNECTOR_METADATA_DIRECTORY="__metadata__"
CONNECTOR_MANIFEST_FILENAME="connector_manifest.json"
MANAGER_SUPPORTED='"manager_supported": *true'
VENV_NAME=".temp_venv"

activate_venv() {
    # Method to activate isolate venv

    # Install dependencies
    requirements_file=$(find "$1" -name "requirements.txt")

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
      echo "✅- Requirements installed for: " "$1"
    else
      echo "❌- Requirements not installed for: " "$1"
    fi
}

deactivate_venv() {
    # Method to deactivate venv and remove the folder
    echo "> Clean Up environment..."
    deactivate
    rm -rf "$1"
}

# Find all parents directory of connector with config loader
# printf action with the %h format specifier, which prints the directory part (parent directory) of the file path
connector_directories_path=$(find . -name "$CONNECTOR_METADATA_DIRECTORY" -printf '%h\n')

# Loop in each connector directory with infos
for connector_directory_path in $connector_directories_path
do
  if [ -d "$connector_directory_path" ]; then
    if grep -q "$MANAGER_SUPPORTED" "$connector_directory_path/$CONNECTOR_METADATA_DIRECTORY/$CONNECTOR_MANIFEST_FILENAME"; then
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

generate_manifest=$(find . -name "generate_connectors_manifest.py")
echo -e "\nGenerating manifest file..."
python "$generate_manifest"

# Ensure manifest is created
manifest_exists=$(find "$(pwd)" -name "manifest.json")

if [ -f "$manifest_exists" ]; then
  echo "✅- Manifest well created !"
else
  echo "❌- Manifest not created !"
fi

