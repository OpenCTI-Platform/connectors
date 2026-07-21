#!/usr/bin/env bash
#MISE description="Generate JSON schema for Connector configuration based on the manifest and configuration definition"
#MISE alias=["generate_schema", "gs"]
#MISE arg "[connector_directory]" help="Path to the connector directory (defaults to current working directory)"
#MISE dir="{{cwd}}"

set -euox pipefail

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/_helpers.sh"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO_ROOT=$(jj root 2>/dev/null || git rev-parse --show-toplevel)
CONNECTOR_METADATA_DIRECTORY="__metadata__"
VENV_NAME=".temp_venv"

CONNECTOR_DIRECTORY="${1:-$(pwd)}"
CONNECTOR_NAME=$(basename "$CONNECTOR_DIRECTORY")
VENV_PATH="$CONNECTOR_DIRECTORY/$VENV_NAME"

# ---------------------------------------------------------------------------
# Virtual-environment lifecycle
# ---------------------------------------------------------------------------
activate_venv() {
    # Create an isolated virtual environment inside the connector directory,
    # activate it, and install the connector's dependencies.
    local connector_dir="$1"

    uv venv -c "$VENV_PATH"

    # Activate — support both Unix and Windows layouts
    if [ -f "$VENV_PATH/bin/activate" ]; then
        # shellcheck disable=SC1091
        . "$VENV_PATH/bin/activate"
    elif [ -f "$VENV_PATH/Scripts/activate" ]; then
        # shellcheck disable=SC1091
        . "$VENV_PATH/Scripts/activate"
    else
        log_error "❌ Could not locate venv activate script in $VENV_PATH"
        return 1
    fi

    pushd "$connector_dir" > /dev/null
    log_step "Installing dependencies in: $connector_dir"

    local requirements_file
    requirements_file=$(find_shallowest_file "." "requirements.txt")

    if [ -n "$requirements_file" ]; then
        uv pip install -r "$requirements_file"
    else
        # Fall back to installing the package itself (assumes pyproject.toml)
        uv pip install .
    fi

    # Ensure connectors-sdk is available for script generation
    echo "🔄 Installing connectors-sdk for schema generation..."
    uv pip install "connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk"

    popd > /dev/null

    if [ -d "$VENV_PATH" ]; then
        log_info "✅ Dependencies installed for: $connector_dir"
    else
        log_error "❌ Dependencies not installed for: $connector_dir"
        return 1
    fi
}

cleanup() {
    log_step "Cleaning up environment..."
    # Remove any temp copies of generator scripts
    rm -f "$CONNECTOR_DIRECTORY/generate_connector_config_json_schema_tmp.py"
    rm -f "$CONNECTOR_DIRECTORY/generate_connector_config_doc_tmp.py"
    # deactivate is a shell function sourced from the venv — guard against it
    # not being available (e.g. if activation failed).
    if command -v deactivate &> /dev/null; then
        deactivate
    fi
    rm -rf "$VENV_PATH"
}

# Always clean up, even on error / Ctrl-C
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

# Ensure the metadata directory exists
metadata_path="$CONNECTOR_DIRECTORY/$CONNECTOR_METADATA_DIRECTORY"
if [ ! -d "$metadata_path" ]; then
    log_warn "Warning: No $CONNECTOR_METADATA_DIRECTORY directory found in $CONNECTOR_DIRECTORY"
    log_warn "Creating metadata directory..."
    mkdir -p "$metadata_path"
fi

# Check if connector is verified
manifest_path="$metadata_path/connector_manifest.json"
if [ -f "$manifest_path" ]; then
    if ! grep -q '"manager_supported": true' "$manifest_path"; then
        log_warn "Warning: Connector is not manager supported in manifest (requires \"manager_supported\": true)."
        log_warn "This connector may not support config schema generation."
        exit 1
    fi
else
    log_warn "Warning: No connector_manifest.json found in $metadata_path"
    log_warn "This connector may not support config schema generation."
    exit 1
fi

echo ""
log_info "Processing connector: $CONNECTOR_NAME"
log_step "Looking for a config model in $CONNECTOR_DIRECTORY"

requirements_file=$(find_shallowest_file "$CONNECTOR_DIRECTORY" "requirements.txt")
pyproject_toml=$(find_shallowest_file "$CONNECTOR_DIRECTORY" "pyproject.toml")

# Verify that the connector actually depends on pydantic-settings / connectors-sdk
if [[ -n "$requirements_file" ]] && grep -qE 'pydantic-settings|connectors-sdk' "$requirements_file"; then
    log_step "Found dependency source: $requirements_file"
elif [[ -n "$pyproject_toml" ]] && grep -q 'connectors-sdk' "$pyproject_toml"; then
    log_step "Found dependency source: $pyproject_toml"
else
    log_warn "Warning: pydantic-settings and connectors-sdk not found in connector's dependencies"
    log_warn "This connector may not support config schema generation."
    exit 1
fi

# Locate generator scripts before doing any heavy work (fail fast)
schema_generator_path=$(find "$REPO_ROOT" -type f -name "generate_connector_config_json_schema.py.sample" | head -n1)
doc_generator_path=$(find "$REPO_ROOT" -type f -name "generate_connector_config_doc.py.sample" | head -n1)

if [ -z "$schema_generator_path" ]; then
    log_error "❌ Could not find generate_connector_config_json_schema.py.sample in $REPO_ROOT"
    exit 1
fi
if [ -z "$doc_generator_path" ]; then
    log_error "❌ Could not find generate_connector_config_doc.py.sample in $REPO_ROOT"
    exit 1
fi

log_info "Found pydantic-settings and/or connectors-sdk in dependencies. Proceeding with schema generation..."

# ---------------------------------------------------------------------------
# Main work
# ---------------------------------------------------------------------------

activate_venv "$CONNECTOR_DIRECTORY"

# --- JSON schema -----------------------------------------------------------
log_step "Generating connector JSON schema..."

# The generator script uses relative imports (e.g. "from src import ...",
# "from connector import ...") that rely on the script living inside the
# connector directory.  Copy it in, run it, then remove it (the EXIT trap
# guarantees removal even on failure).

cp "$schema_generator_path" "$CONNECTOR_DIRECTORY/generate_connector_config_json_schema_tmp.py"
(cd "$CONNECTOR_DIRECTORY" && python generate_connector_config_json_schema_tmp.py)
rm -f "$CONNECTOR_DIRECTORY/generate_connector_config_json_schema_tmp.py"
log_info "✅ JSON schema generated successfully"

# --- Configuration documentation -------------------------------------------
log_step "Generating configurations table..."

uv pip install -qq jsonschema_markdown

cp "$doc_generator_path" "$CONNECTOR_DIRECTORY/generate_connector_config_doc_tmp.py"
(cd "$CONNECTOR_DIRECTORY" && python generate_connector_config_doc_tmp.py)
rm -f "$CONNECTOR_DIRECTORY/generate_connector_config_doc_tmp.py"
log_info "✅ Configuration documentation generated successfully"

# ---------------------------------------------------------------------------
# Done  (cleanup_venv runs automatically via the EXIT trap)
# ---------------------------------------------------------------------------
echo ""
log_info "✅ Schema generation completed for connector: $CONNECTOR_NAME"
echo ""
log_info "Done!"
