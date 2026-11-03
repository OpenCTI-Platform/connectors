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
# Pinned on purpose: some connectors require 3.12 (none require 3.11 strictly).
# Without this, uv picks whatever interpreter it happens to discover, which
# varies between the CI runner image and each developer's machine.
PYTHON_VERSION="3.12"
# Ref the connectors-sdk is installed from. Release/LTS builds set RELEASE_REF
# so their schemas are generated against the matching SDK instead of master.
SDK_REF="${RELEASE_REF:-master}"
# Where the connectors-sdk is installed from: "git" (GitHub at SDK_REF) or "local"
# (this checkout's connectors-sdk/, so SDK changes that are not merged yet are
# picked up). Defaults to "git" in CI (CI is set, as on GitHub Actions) and to
# "local" elsewhere; force one with e.g. `SDK_SOURCE=git mise run gs <connector_directory>`.
if [[ -n "${CI:-}" ]]; then
    SDK_SOURCE="${SDK_SOURCE:-git}"
else
    SDK_SOURCE="${SDK_SOURCE:-local}"
fi
SDK_REPO_URL="https://github.com/OpenCTI-Platform/connectors.git"
# Shallow, sparse checkouts of connectors-sdk, one per commit, reused across
# connectors so a full run fetches the SDK once instead of once per connector.
SDK_CACHE_DIR="${SDK_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/opencti-connectors-sdk}"

CONNECTOR_DIRECTORY="${1:-$(pwd)}"
CONNECTOR_NAME=$(basename "$CONNECTOR_DIRECTORY")
VENV_PATH="$CONNECTOR_DIRECTORY/$VENV_NAME"

# ---------------------------------------------------------------------------
# connectors-sdk source
# ---------------------------------------------------------------------------
# Both functions below run inside `$(...)`, where bash (3.2 on macOS, no
# inherit_errexit) ignores `set -e`: every step that can fail returns
# explicitly, so the caller's assignment fails and stops the script.
resolve_sdk_ref_sha() {
    # Print the commit SHA SDK_REF points to: branch first, then tag (peeled
    # when annotated). A ref that matches nothing is taken as a commit SHA.
    local refs sha
    if ! refs=$(git ls-remote "$SDK_REPO_URL" \
        "refs/heads/$SDK_REF" "refs/tags/$SDK_REF" "refs/tags/$SDK_REF^{}"); then
        log_error "❌ Could not resolve connectors-sdk ref '$SDK_REF' on $SDK_REPO_URL"
        return 1
    fi
    sha=$(awk -v ref="$SDK_REF" '
        $2 == "refs/heads/" ref      { head = $1 }
        $2 == "refs/tags/" ref "^{}" { peeled = $1 }
        $2 == "refs/tags/" ref       { tag = $1 }
        END { print (head != "" ? head : (peeled != "" ? peeled : tag)) }
    ' <<< "$refs")
    echo "${sha:-$SDK_REF}"
}

fetch_sdk() {
    # Print the path of a checkout of connectors-sdk at SDK_REF, fetching it
    # first when it is not cached. Only the connectors-sdk/ directory of the
    # SDK_REF commit is downloaded: no history, no other connector.
    local sha checkout tmp
    sha=$(resolve_sdk_ref_sha) || return 1
    checkout="$SDK_CACHE_DIR/$sha"

    if [ ! -f "$checkout/connectors-sdk/pyproject.toml" ]; then
        mkdir -p "$SDK_CACHE_DIR" || return 1
        # Temp dirs of runs interrupted more than an hour ago (Ctrl-C).
        find "$SDK_CACHE_DIR" -mindepth 1 -maxdepth 1 -name '.fetch.*' -mmin +60 \
            -exec rm -rf {} + 2>/dev/null || true
        tmp=$(mktemp -d "$SDK_CACHE_DIR/.fetch.XXXXXX") || return 1
        if ! {
            git -C "$tmp" init -q &&
                git -C "$tmp" remote add origin "$SDK_REPO_URL" &&
                git -C "$tmp" sparse-checkout set connectors-sdk &&
                git -C "$tmp" fetch -q --depth 1 --filter=blob:none origin "$sha" &&
                git -C "$tmp" -c advice.detachedHead=false checkout -q FETCH_HEAD &&
                [ -f "$tmp/connectors-sdk/pyproject.toml" ]
        }; then
            rm -rf "$tmp"
            log_error "❌ Could not fetch connectors-sdk at $sha from $SDK_REPO_URL"
            return 1
        fi
        # Only a complete checkout is ever moved to $checkout. A concurrent run
        # may have cached the same commit in the meantime.
        # mv then moves $tmp inside its checkout instead of failing (BSD mv has
        # no -T): remove that nested copy, or $tmp when mv failed.
        mv "$tmp" "$checkout" 2>/dev/null || true
        rm -rf "$tmp" "${checkout:?}/${tmp##*/}"
    fi

    echo "$checkout/connectors-sdk"
}

# ---------------------------------------------------------------------------
# Virtual-environment lifecycle
# ---------------------------------------------------------------------------
activate_venv() {
    # Create an isolated virtual environment inside the connector directory,
    # activate it, and install the connector's dependencies.
    local connector_dir="$1"

    uv venv -c --python "$PYTHON_VERSION" "$VENV_PATH"

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

    # Schemas are generated against one connectors-sdk, whatever the connector
    # pins: the override replaces its connectors-sdk requirement (usually
    # `connectors-sdk @ git+...`), so uv never clones the whole monorepo.
    local sdk_path
    if [[ "$SDK_SOURCE" == "local" ]]; then
        sdk_path="$REPO_ROOT/connectors-sdk"
        echo "🔄 Using local connectors-sdk ($sdk_path) for schema generation..."
    else
        echo "🔄 Fetching connectors-sdk ($SDK_REF) for schema generation..."
        sdk_path=$(fetch_sdk)
    fi
    # A plain path, not a file:// URL: uv accepts it and it needs no escaping
    # (spaces, Windows drive letters).
    local sdk_requirement="connectors-sdk @ $sdk_path"
    # Absolute: VENV_PATH may be relative and the install runs from the
    # connector directory.
    local overrides_file
    overrides_file="$(cd "$VENV_PATH" && pwd)/sdk-overrides.txt"
    echo "$sdk_requirement" > "$overrides_file"

    pushd "$connector_dir" > /dev/null
    log_step "Installing dependencies in: $connector_dir"

    local requirements_file
    requirements_file=$(find_shallowest_file "." "requirements.txt")

    # connectors-sdk is listed explicitly too, for connectors that only depend
    # on pydantic-settings: the override alone would not add it.
    # --reinstall-package rebuilds it from source every time: uv would
    # otherwise reuse a cached wheel of the SDK and could miss an edit.
    if [ -n "$requirements_file" ]; then
        uv pip install --reinstall-package connectors-sdk --overrides "$overrides_file" \
            -r "$requirements_file" "$sdk_requirement"
    else
        # Fall back to installing the package itself (assumes pyproject.toml)
        uv pip install --reinstall-package connectors-sdk --overrides "$overrides_file" \
            . "$sdk_requirement"
    fi

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

if [[ "$SDK_SOURCE" != "git" && "$SDK_SOURCE" != "local" ]]; then
    log_error "❌ Invalid SDK_SOURCE '$SDK_SOURCE': expected 'git' or 'local'."
    exit 1
fi

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
