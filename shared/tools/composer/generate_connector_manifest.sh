#!/bin/bash

set -e  # exit on error

find_connector_directory() {
  # Method to find the highest directory with given connector's name in the repo.

  # find: find all directories with given name recursively
  # awk: count path length
  # sort: sort by path length
  # head: take the first directory
  # cut: get directory path only
  find . -type d -iname "$1" \
    | awk -F/ '{print NF, $0}' \
    | sort -n \
    | head -n1 \
    | cut -d' ' -f2-
}

CONNECTOR_METADATA_DIRECTORY="__metadata__"

echo "Adding metadata info for a connector..."

read -p "In which existing connector?(give connector folder name) " CONNECTOR_NAME

CONNECTOR_DIRECTORY=$(find_connector_directory "$CONNECTOR_NAME")

echo "Found this directory : " "$CONNECTOR_DIRECTORY"

read -p "Is it the correct connector?(y/n) " ANSWER

if [[ "${ANSWER,,}" =~ ('y') ]]; then
	echo "Adding info file for: " "$CONNECTOR_NAME"
	    mkdir -p "$CONNECTOR_DIRECTORY/$CONNECTOR_METADATA_DIRECTORY"

      # create metadata info
      metadata_path=$(find . -name "connector_manifest.json.sample")
      cp "$metadata_path" "$CONNECTOR_DIRECTORY/$CONNECTOR_METADATA_DIRECTORY/connector_manifest.json"

      echo "You can complete metadata for the connector."

else
	echo "OK, then see you :)"
fi