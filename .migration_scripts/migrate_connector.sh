#!/bin/bash

set -euo pipefail

connector_dir="$1"

# Skip if already migrated
if [ -f "$connector_dir/__metadata__/connector_config_schema.json" ]; then
  echo "✅ Connector already migrated: $connector_dir"
  exit 0
fi

# Migrate connector
python .migration_scripts/migrate_connector.py --connector-path="$connector_dir"

# Find test requirements
echo 'Running tests...'
test_requirements_file=$(find "$connector_dir" -type f -name "test-requirements.txt" | head -n 1 || true)
if [ -z "$test_requirements_file" ]; then
  echo "❌ No test-requirements.txt found in $connector_dir"
  exit 1
fi

# Run tests in temporary venv
venv_name="$connector_dir/.temp_venv"

cleanup_venv() {
  [ -d "$venv_name" ] && rm -rf "$venv_name"
}
trap cleanup_venv EXIT

python -m venv "$venv_name"

# Use venv’s python explicitly
VENV_PY="$venv_name/bin/python"
[ -f "$VENV_PY" ] || VENV_PY="$venv_name/Scripts/python.exe"  # Windows fallback

echo "  > Installing dependencies in .temp_venv..."
"$VENV_PY" -m pip install -q -r "$test_requirements_file"
"$VENV_PY" -m pip check
"$VENV_PY" -m pytest $connector_dir

cleanup_venv
trap - EXIT
