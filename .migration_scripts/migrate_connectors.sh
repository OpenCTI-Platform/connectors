#!/bin/bash

set -euo pipefail

TARGET_DIRS=("external-import" "internal-enrichment" "stream")
venv_name=".temp_venv"

cleanup_venv() {
  [ -d "$venv_name" ] && rm -rf "$venv_name"
}
trap cleanup_venv EXIT

for base in "${TARGET_DIRS[@]}"; do
  for project in "$base"/*; do

    # Skip already migrated connectors
    [ -f "$project/__metadata__/connector_config_schema.json" ] && continue

    # Migrate connector
    python .migration_scripts/migrate_connector.py --connector-path="$project" || continue

    # Find test requirements
    echo 'Running tests...'
    test_requirements_file=$(find "$project" -type f -name "test-requirements.txt" | head -n 1 || true)
    if [ -z "$test_requirements_file" ]; then
      echo "❌ No test-requirements.txt found in $project"
      continue
    fi

    # Run tests in a temporary venv
    (
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
      "$VENV_PY" -m pytest $project

      cleanup_venv
      trap - EXIT
    )
  done
done
