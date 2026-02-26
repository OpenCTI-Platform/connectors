#!/bin/bash

set -eo pipefail  # exit on error

CONNECTOR_METADATA_DIRECTORY="__metadata__"
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
    echo '> Installing requirements in: ' "$1"

    requirements_file=$(find_requirements_txt .)
    if [ -n "$requirements_file" ]; then
      # -qq: Hides both informational and warning messages, showing only errors.
      python -m pip install -qq -r "$requirements_file"
    else
      # If no requirements.txt, try to install the connector as a package (assuming pyproject.toml exists)
      python -m pip install .
    fi

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

# Find all parents directory of connector with __metadata__ directory
connector_directories_path=$(find . -type d -name "$CONNECTOR_METADATA_DIRECTORY" | sed 's:/*'"$CONNECTOR_METADATA_DIRECTORY"'$::' | sort -u)

# Loop in each connector directory with infos and regenerate JSON schema if changed
for connector_directory_path in $connector_directories_path
do
  if [ -d "$connector_directory_path" ]; then
    # Only generate schema for directory that changed
    CIRCLE_BRANCH=${CIRCLE_BRANCH:-""}
    if [ "$CIRCLE_BRANCH" = "release/6.9.x" ]; then
      directory_has_changed=$(git diff HEAD~1 HEAD -- "$connector_directory_path")
    else
      directory_has_changed=$(git diff $(git merge-base release/6.9.x HEAD) HEAD "$connector_directory_path")
    fi

    if [ -z "$directory_has_changed" ] ; then
      echo "Nothing has changed in: " "$connector_directory_path"
    elif grep -q '"manager_supported": false,' "$connector_directory_path"/"$CONNECTOR_METADATA_DIRECTORY"/connector_manifest.json; then
      echo "Connector is not supported: " "$connector_directory_path"
    else
      echo "Changes in: " "$connector_directory_path"
      echo "> Looking for a config model in " "$connector_directory_path"
      
      requirements_file=$(find_requirements_txt "$connector_directory_path")
      pyproject_toml=$(find_pyproject_toml "$connector_directory_path")

      # Check if requirements file contains pydantic-settings or connectors-sdk dependency
      # If not found in requirements.txt and pyproject.toml exists, try to find connectors-sdk in pyproject.toml
      if [[ -n "$requirements_file" ]] && grep -qE 'pydantic-settings|connectors-sdk' "$requirements_file"; then
          echo "Found requirements.txt: $requirements_file"
      elif [[ -n "$pyproject_toml" ]] && grep -q 'connectors-sdk' "$pyproject_toml"; then
          echo "Found pyproject.toml: $pyproject_toml"
      else
          continue
      fi

      (
        echo -e "\033[32mFound pydantic-settings and/or connectors-sdk in dependencies. Proceeding with schema generation...\033[0m"

        activate_venv "$connector_directory_path"

        # Generate connector JSON schema in __metadata__
        generator_path=$(find . -name "generate_connector_config_json_schema.py.sample")
        cp "$generator_path" "$connector_directory_path/generate_connector_config_json_schema_tmp.py"
        python "$connector_directory_path/generate_connector_config_json_schema_tmp.py"
        rm "$connector_directory_path/generate_connector_config_json_schema_tmp.py"

        # Generate configurations table in __metadata/CONNECTOR_CONFIG_DOC.md
        python -m pip install -q --disable-pip-version-check jsonschema_markdown
        generator_config_doc_path=$(find . -name "generate_connector_config_doc.py.sample")
        cp "$generator_config_doc_path" "$connector_directory_path/generate_connector_config_doc_tmp.py"
        python "$connector_directory_path/generate_connector_config_doc_tmp.py"
        rm "$connector_directory_path/generate_connector_config_doc_tmp.py"

        deactivate_venv "$connector_directory_path/$VENV_NAME"
      )
    fi
  fi
done
wait
