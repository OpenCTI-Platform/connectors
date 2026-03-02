#!/bin/bash

# Bash script to generate config JSON schema for a single targeted connector
# This is the singular version of generate_connectors_config_json_schemas.sh

set -euo pipefail  # exit on error

CONNECTOR_METADATA_DIRECTORY="__metadata__"
VENV_NAME=".temp_venv"

find_connector_directories() {
  # Method to find all directories matching the search term
  
  # Clean the search term (remove leading/trailing slashes)
  search_term=$(echo "$1" | sed 's:^/*::' | sed 's:/*$::')
  
  # If search term contains a slash, treat it as a path pattern
  if echo "$search_term" | grep -q '/'; then
    # First try exact match
    exact_match=$(find . -type d -path "*/$search_term" 2>/dev/null | head -n1)
    
    if [ -n "$exact_match" ]; then
      echo "$exact_match"
    else
      # If no exact match, find the root directory matching the pattern
      # Use -maxdepth to limit how deep we search, then filter
      find . -type d -path "*$search_term" -o -type d -path "*$search_term/*" 2>/dev/null \
        | while read dir; do
          # Only output if this is the root match (not a subdirectory of another match)
          parent_match=$(echo "$dir" | grep -o ".*/$search_term")
          if [ -n "$parent_match" ]; then
            echo "$parent_match"
          fi
        done \
        | sort -u \
        | head -n1
    fi
  else
    # Search for directory name - but only connector roots
    # Look for directories with requirements.txt, src/, or __metadata__/
    find . -type d -iname "*$search_term*" 2>/dev/null \
      | while read dir; do
          # Check if it's likely a connector root
          if [ -f "$dir/requirements.txt" ] || [ -d "$dir/src" ] || [ -d "$dir/__metadata__" ]; then
            echo "$dir"
          fi
        done \
      | awk -F/ '{print NF, $0}' \
      | sort -n \
      | cut -d' ' -f2-
  fi
}

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

find_pyproject_toml() {
  # Method to find the highest pyproject.toml in connector's tree

  # find: find all pyproject.toml recursively
  # awk: count path length
  # sort: sort by path length
  # head: take the first file
  # cut: get file path only
  find "$1" -type f -name "pyproject.toml" \
    | awk -F/ '{print NF, $0}' \
    | sort -n \
    | head -n1 \
    | cut -d' ' -f2-
}

activate_venv() {
    # Method to activate isolate venv

    # Create isolated virtual environment in connector path
    python -m venv "$1/$VENV_NAME"

    # Activate virtual environment according to OS
    if [ -f "$1/$VENV_NAME/bin/activate" ]; then
      . "$1/$VENV_NAME/bin/activate"  # Linux/MacOS
    elif [ -f "$1/$VENV_NAME/Scripts/activate" ]; then
      . "$1/$VENV_NAME/Scripts/activate"  # Windows
    fi

    # Install dependencies from connector's directory
    pushd "$1"
    echo '> Installing dependencies in: ' "$1"

    requirements_file=$(find_requirements_txt .)
    if [ -n "$requirements_file" ]; then
      # -qq: Hides both informational and warning messages, showing only errors.
      python -m pip install -qq -r "$requirements_file"
    else
      # If no requirements.txt, try to install the connector as a package (assuming pyproject.toml exists)
      python -m pip install .
    fi

    # Ensure connectors-sdk is available for script generation
    echo "🔄 Installing connectors-sdk for schema generation..."
    python -m pip install "connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk"

    # Return to original working directory
    popd

    # Check if venv is well created
    venv_exists=$(find "$1" -name ".temp_venv")

    if [ -d "$venv_exists" ]; then
      echo "✅ Dependencies installed for: " "$1"
    else
      echo "❌ Dependencies not installed for: " "$1"
    fi
}

deactivate_venv() {
    # Method to deactivate venv and remove the folder
    echo "> Cleaning up environment..."
    deactivate
    rm -rf "$1"
}

# Main script
echo -e "\033[36mGenerating config JSON schemas for a single connector...\033[0m"
echo ""

# Ask for connector name
read -p "Which connector do you want to generate schemas for? (give connector folder name) " CONNECTOR_NAME

# Find matching connector directories
# Bash 3.2 does not support process substitution in arrays, so we use a workaround
matching_directories=$(find_connector_directories "$CONNECTOR_NAME")
IFS=$'\n' read -r -a matching_directories <<< "$matching_directories"

if [ ${#matching_directories[@]} -eq 0 ]; then
    echo -e "\033[31mNo connector found matching: '$CONNECTOR_NAME'\033[0m"
    echo -e "\033[33mPlease check the connector name and try again.\033[0m"
    exit 1
fi

# Select the connector directory
CONNECTOR_DIRECTORY=""

if [ ${#matching_directories[@]} -eq 1 ]; then
    # Only one match found
    CONNECTOR_DIRECTORY="${matching_directories[0]}"
    # Remove leading ./ from path for cleaner display
    clean_path=$(echo "$CONNECTOR_DIRECTORY" | sed 's:^\./::' )
    echo -e "\033[33mFound this directory: $clean_path\033[0m"
    
    # Ask for confirmation
    read -p "Is this the correct connector? (y/n) " ANSWER
    
    ANSWER_LOWER=$(echo "$ANSWER" | tr '[:upper:]' '[:lower:]')
    if [[ ! "$ANSWER_LOWER" =~ ^y ]]; then
        echo -e "\033[33mAborted by user.\033[0m"
        exit 0
    fi
else
    # Multiple matches found
    echo -e "\033[33mFound multiple connectors matching '$CONNECTOR_NAME':\033[0m"
    echo ""
    
    for i in "${!matching_directories[@]}"; do
        # Remove leading ./ from path for cleaner display
        clean_path=$(echo "${matching_directories[$i]}" | sed 's:^\./::')
        echo "  [$((i+1))] $clean_path"
    done
    echo "  [0] Cancel"
    echo ""
    
    read -p "Please select the connector you want to process (enter number): " selection
    
    if [ "$selection" = "0" ] || [ -z "$selection" ]; then
        echo -e "\033[33mAborted by user.\033[0m"
        exit 0
    fi
    
    # Validate selection is a number and in range
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        index=$((selection - 1))
        if [ $index -ge 0 ] && [ $index -lt ${#matching_directories[@]} ]; then
            CONNECTOR_DIRECTORY="${matching_directories[$index]}"
            clean_path=$(echo "$CONNECTOR_DIRECTORY" | sed 's:^\./::' )
            echo ""
            echo -e "\033[32mSelected: $clean_path\033[0m"
        else
            echo -e "\033[31mInvalid selection.\033[0m"
            exit 1
        fi
    else
        echo -e "\033[31mInvalid selection.\033[0m"
        exit 1
    fi
fi

# Check if metadata directory exists
metadata_path="$CONNECTOR_DIRECTORY/$CONNECTOR_METADATA_DIRECTORY"
if [ ! -d "$metadata_path" ]; then
    echo -e "\033[33mWarning: No $CONNECTOR_METADATA_DIRECTORY directory found in $CONNECTOR_DIRECTORY\033[0m"
    echo -e "\033[33mCreating metadata directory...\033[0m"
    mkdir -p "$metadata_path"
fi

# Check if connector is supported
manifest_path="$metadata_path/connector_manifest.json"
is_not_supported=false
if [ -f "$manifest_path" ]; then
    if grep -q '"manager_supported": false' "$manifest_path"; then
        is_not_supported=true
        echo -e "\033[33mWarning: Connector is marked as not supported in manifest.\033[0m"
        read -p "Do you want to continue anyway? (y/n) " continue_answer
        continue_answer_lower=$(echo "$continue_answer" | tr '[:upper:]' '[:lower:]')
        if [[ ! "$continue_answer_lower" =~ ^y ]]; then
            echo -e "\033[33mAborted by user.\033[0m"
            exit 0
        fi
    fi
fi

echo ""
echo -e "\033[32mProcessing connector: $CONNECTOR_NAME\033[0m"
echo "> Looking for a config model in $CONNECTOR_DIRECTORY"

requirements_file=$(find_requirements_txt "$CONNECTOR_DIRECTORY")
pyproject_toml=$(find_pyproject_toml "$CONNECTOR_DIRECTORY")

# Check if requirements file contains pydantic-settings or connectors-sdk dependency
# If not found in requirements.txt and pyproject.toml exists, try to find connectors-sdk in pyproject.toml
if [[ -n "$requirements_file" ]] && grep -qE 'pydantic-settings|connectors-sdk' "$requirements_file"; then
    echo "Found requirements.txt: $requirements_file"
elif [[ -n "$pyproject_toml" ]] && grep -q 'connectors-sdk' "$pyproject_toml"; then
    echo "Found pyproject.toml: $pyproject_toml"
else
    echo -e "\033[33mWarning: pydantic-settings and connectors-sdk not found in connector's dependencies\033[0m"
    echo -e "\033[33mThis connector may not support config schema generation.\033[0m"
    exit 1
fi

echo -e "\033[32mFound pydantic-settings and/or connectors-sdk in dependencies. Proceeding with schema generation...\033[0m"

(
    # Activate virtual environment
    activate_venv "$CONNECTOR_DIRECTORY"
                
    echo -e "\033[36m> Generating connector JSON schema...\033[0m"
    
    # Generate connector JSON schema in __metadata__
    generator_path=$(find . -name "generate_connector_config_json_schema.py.sample")
    if [ -n "$generator_path" ]; then
        cp "$generator_path" "$CONNECTOR_DIRECTORY/generate_connector_config_json_schema_tmp.py"
        python "$CONNECTOR_DIRECTORY/generate_connector_config_json_schema_tmp.py"
        rm "$CONNECTOR_DIRECTORY/generate_connector_config_json_schema_tmp.py"
        echo -e "\033[32m✅ JSON schema generated successfully\033[0m"
    else
        echo -e "\033[31m❌ Could not find generate_connector_config_json_schema.py.sample\033[0m"
    fi
    
    echo -e "\033[36m> Generating configurations table...\033[0m"
    
    # Generate configurations table in __metadata/CONNECTOR_CONFIG_DOC.md
    python -m pip install -q --disable-pip-version-check jsonschema_markdown
    
    generator_config_doc_path=$(find . -name "generate_connector_config_doc.py.sample")
    if [ -n "$generator_config_doc_path" ]; then
        cp "$generator_config_doc_path" "$CONNECTOR_DIRECTORY/generate_connector_config_doc_tmp.py"
        python "$CONNECTOR_DIRECTORY/generate_connector_config_doc_tmp.py"
        rm "$CONNECTOR_DIRECTORY/generate_connector_config_doc_tmp.py"
        echo -e "\033[32m✅ Configuration documentation generated successfully\033[0m"
    else
        echo -e "\033[31m❌ Could not find generate_connector_config_doc.py.sample\033[0m"
    fi
    
    # Clean up virtual environment
    deactivate_venv "$CONNECTOR_DIRECTORY/$VENV_NAME"
)

echo ""
echo -e "\033[32m✅ Schema generation completed for connector: $CONNECTOR_NAME\033[0m"

echo ""
echo -e "\033[32mDone!\033[0m"
