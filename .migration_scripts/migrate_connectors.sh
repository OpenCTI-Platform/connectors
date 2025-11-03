#!/bin/bash

set -euo pipefail

# Set python stdout/stderr encoding in order to write to log files
export PYTHONIOENCODING=utf8
export MAX_JOBS=4

TARGET_DIRS=("external-import" "internal-enrichment" "stream")
CONNECTOR_METADATA_DIRECTORY="__metadata__"
LOG_DIR=".migration_scripts/logs"


# Create a new clean venv for one connector.
new_venv() {
  project=$1

  venv="$project/.temp_venv"

  # Create clean venv
  rm -rf "$venv"
  python -m venv "$venv"
}

# Remove the venv of one connector.
rm_venv() {
  project=$1

  venv="$project/.temp_venv"

  rm -rf "$venv"
}

# Get the python path from the venv of a connector.
get_venv_python() {
  project=$1

  venv="$project/.temp_venv"
  python="$venv/bin/python"
  [ -f "$python" ] || python="$venv/Scripts/python.exe"  # Windows fallback

  echo "$python"
}

is_in_connectors_list() {
  project=$1

  connectors=(
    "external-import/abuseipdb-ipblacklist"
    "external-import/cpe"
    "external-import/disarm-framework"
    "external-import/malwarebazaar"
    "external-import/malwarebazaar-recent-additions"
    "external-import/microsoft-sentinel-incidents"
    "external-import/mitre-atlas"
    "external-import/phishunt"
    "external-import/proofpoint-tap"
    "external-import/red-flag-domains"
    "external-import/shadowserver"
    "external-import/tenable-vuln-management"
    "external-import/urlhaus"
    "external-import/urlhaus-recent-payloads"
    "external-import/valhalla"
    "external-import/wiz"
    "internal-enrichment/anyrun-task"
    "internal-enrichment/dnstwist"
    "internal-enrichment/joe-sandbox"
    "internal-enrichment/recordedfuture-enrichment"
  )

  # connectors=(
  #   "external-import/doppel"
  #   "external-import/group-ib"
  #   "external-import/ibm-xti"
  #   "external-import/infoblox"
  #   "external-import/ipsum"
  #   "external-import/malcore"
  #   "external-import/microsoft-defender-incidents"
  #   "external-import/proofpoint-et-reputation"
  #   "external-import/servicenow"
  #   "external-import/threatmatch"
  #   "external-import/vulncheck"
  #   "external-import/vxvault"
  #   "external-import/zerofox"
  #   "internal-enrichment/greynoise-vuln"
  #   "internal-enrichment/hybrid-analysis-sandbox"
  #   "internal-enrichment/proofpoint-et-intelligence"
  #   "internal-enrichment/yara"
  #   "stream/sumologic-intel"
  #   "stream/zscaler"
  # )

  # Check if given project path is in connectors list
  printf '%s\n' "${connectors[@]}" | grep -Fxq "$project"
}

# # Check whether a connector is "verified" or not.
# is_verified() {
#   project=$1

#   manifest="$project/$CONNECTOR_METADATA_DIRECTORY/connector_manifest.json"

#   # TIP: Change the condition to catch all verified connectors (even without verification date)
#   grep -q '"verified": true' "$manifest" 2>/dev/null &&
#   ! grep -q '"last_verified_date": null' "$manifest" 2>/dev/null
# }

# Run `.migration_scripts/migrate_connector.py` for one connector.
# This script will modify the connector codebase to make it "manager supported".
migrate_connector() {
  project=$1

  log_file="$LOG_DIR/$(basename "$project").log"

  # Migrate connector
  echo "⌛ $project: Start migration..."

  {
    python .migration_scripts/migrate_connector.py --connector-path="$project" || return 1
  } >>"$log_file" 2>&1

  echo "✅ $project: Successfully migrated"
}

# Run `generate_connector_config_json_schema_tmp.py` for one connector.
generate_config_json_schema() {
  project=$1

  log_file="$LOG_DIR/$(basename "$project").log"

  # Generate connector JSON schema in __metadata__
  echo -e "\033[36m⌛ $project: Generating config JSON schema... \033[0m"

  requirements_file=$(find "$project" -type f -name "requirements.txt" | head -n 1 || true)
  if [ -z "$requirements_file" ]; then
    echo -e "\033[36m❌ $project: No requirements.txt found \033[0m"
    return 1
  fi

  sample_script_path="./shared/tools/composer/generate_connectors_config_schemas/generate_connector_config_json_schema.py.sample"
  cp "$sample_script_path" "$project/generate_connector_config_json_schema_tmp.py"

  # Use explicit python path to avoid collision with "global" python
  python=$(get_venv_python "$project")

  {
    # Replace connectors-sdk by local module for performance reason
    sed -i \
    's|connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk|./connectors-sdk|g' \
    "$requirements_file"

    # -qq: Hides both informational and warning messages, showing only errors.
    "$python" -m pip install -qq -r "$requirements_file" || return 1

    # Reset requirements.txt
    sed -i \
    's|./connectors-sdk|connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk|g' \
    "$requirements_file"

    "$python" "$project/generate_connector_config_json_schema_tmp.py" || return 1
  } >>"$log_file" 2>&1

  rm "$project/generate_connector_config_json_schema_tmp.py"
  
  echo -e "\033[36m✅ $project: Config JSON schema successfully generated \033[0m"
}

test_connector() {
  project=$1

  log_file="$LOG_DIR/$(basename "$project").log"

  # Find test requirements
  echo -e "\033[33m⌛ $project: Running tests... \033[0m"

  requirements_file=$(find "$project" -type f -name "requirements.txt" | head -n 1 || true)
  test_requirements_file=$(find "$project" -type f -name "test-requirements.txt" | head -n 1 || true)
  if [ -z "$test_requirements_file" ]; then
    echo -e "\033[33m❌ $project: No test-requirements.txt found \033[0m"
    return 1
  fi

  # Use explicit python path to avoid collision with "global" python
  python=$(get_venv_python "$project")

  {
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

    "$python" -m pytest $project || return 1
  } >>"$log_file" 2>&1

  echo -e "\033[33m✅ $project: All tests successfully passed \033[0m"
}

# Clean logs
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

# Migrate each connector
for base in "${TARGET_DIRS[@]}"; do
  for project in "$base"/*; do
    if is_in_connectors_list "$project"; then
      # Skip connectors already "manager supported"
      if [ -f "$project/$CONNECTOR_METADATA_DIRECTORY/connector_config_schema.json" ]; then
        echo -e "\033[90m👌 $project: Already manager supported \033[0m"
      else
        (
          migrate_connector "$project" || {
            echo "❌ $project: Migration failed, skipping connector"
            exit 0
          }

          new_venv "$project"

          generate_config_json_schema "$project" || {
            echo -e "\033[36m❌ $project: Generation of config JSON schema failed, skipping connector \033[0m"
            rm_venv "$project"
            exit 0
          }

          test_connector "$project" || {
            echo -e "\033[33m❌ $project: Tests failed, skipping connector \033[0m"
            rm_venv "$project"
            exit 0
          }

          rm_venv "$project"
        ) &
      fi
    fi
  done
done
wait

echo "📄 See logs for more details:"
for f in $(ls "$LOG_DIR" | sort); do
  echo "$LOG_DIR/$f"
done
