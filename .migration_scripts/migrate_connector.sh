#!/bin/bash

set -euo pipefail

connector_dir="$1"

# Create a new clean venv for one connector.
new_venv() {
  venv="$connector_dir/.temp_venv"

  # Create clean venv
  rm -rf "$venv"
  python -m venv "$venv"
}

# Remove the venv of one connector.
rm_venv() {
  venv="$connector_dir/.temp_venv"

  rm -rf "$venv"
}

# Get the python path from the venv of a connector.
get_venv_python() {
  venv="$connector_dir/.temp_venv"
  python="$venv/bin/python"
  [ -f "$python" ] || python="$venv/Scripts/python.exe"  # Windows fallback

  echo "$python"
}

# Run `.migration_scripts/migrate_connector.py` for one connector.
# This script will modify the connector codebase to make it "manager supported".
migrate_connector() {
  echo "⌛ $connector_dir: Start migration..."

  python .migration_scripts/migrate_connector.py --connector-path="$connector_dir" || return 1

  echo "✅ $connector_dir: Successfully migrated"
}

# Run `generate_connector_config_json_schema_tmp.py` for one connector.
# This script will generate connector JSON schema in __metadata__ directory.
generate_config_json_schema() {
  echo -e "\033[36m⌛ $connector_dir: Generating config JSON schema... \033[0m"

  requirements_file=$(find "$connector_dir" -type f -name "requirements.txt" | head -n 1 || true)
  if [ -z "$requirements_file" ]; then
    echo -e "\033[36m❌ $connector_dir: No requirements.txt found \033[0m"
    return 1
  fi

  sample_script_path="./shared/tools/composer/generate_connectors_config_schemas/generate_connector_config_json_schema.py.sample"
  cp "$sample_script_path" "$connector_dir/generate_connector_config_json_schema_tmp.py"

  # Use explicit python path to avoid collision with "global" python
  python=$(get_venv_python "$connector_dir")

  # Replace connectors-sdk by local module for performance reason
  sed -i \
  's|connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk|./connectors-sdk|g' \
  "$requirements_file"
  
  # -qq: Hides both informational and warning messages, showing only errors.
  "$python" -m pip install -r "$requirements_file" || return 1

  # Reset requirements.txt
  sed -i \
  's|./connectors-sdk|connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk|g' \
  "$requirements_file"

  "$python" "$connector_dir/generate_connector_config_json_schema_tmp.py" || return 1

  rm "$connector_dir/generate_connector_config_json_schema_tmp.py"
  
  echo -e "\033[36m✅ $connector_dir: Config JSON schema successfully generated \033[0m"
}

test_connector() {
  # Find test requirements
  echo -e "\033[33m⌛ $connector_dir: Running tests... \033[0m"
  
  requirements_file=$(find "$connector_dir" -type f -name "requirements.txt" | head -n 1 || true)
  test_requirements_file=$(find "$connector_dir" -type f -name "test-requirements.txt" | head -n 1 || true)
  if [ -z "$test_requirements_file" ]; then
    echo -e "\033[33m❌ $connector_dir: No test-requirements.txt found \033[0m"
    return 1
  fi

  # Use explicit python path to avoid collision with "global" python
  python=$(get_venv_python "$connector_dir")

  # Replace connectors-sdk by local module for performance reason
  sed -i \
  's|connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk|./connectors-sdk|g' \
  "$requirements_file"

  # -qq: Hides both informational and warning messages, showing only errors.
  "$python" -m pip install -r "$test_requirements_file" || return 1

  # Reset requirements.txt
  sed -i \
  's|./connectors-sdk|connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk|g' \
  "$requirements_file"

  "$python" -m pytest $connector_dir || return 1
}

# Skip if already migrated
if [ -f "$connector_dir/__metadata__/connector_config_schema.json" ]; then
  echo "👌 $connector_dir: Already manager supported"
  exit 0
fi


migrate_connector "$connector_dir" || {
  echo "❌ $connector_dir: Migration failed"
  exit 1
}

new_venv "$connector_dir"

generate_config_json_schema "$connector_dir" || {
  echo "❌ $connector_dir: Generation of config JSON schema failed"
  rm_venv "$connector_dir"
  exit 1
}

test_connector "$connector_dir" || {
  echo "❌ $connector_dir: Tests failed"
  rm_venv "$connector_dir"
  exit 1
}

rm_venv "$connector_dir"
