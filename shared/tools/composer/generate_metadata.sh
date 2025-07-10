#!/bin/bash

set -e  # exit on error

CONNECTOR_INFOS_DIRECTORY="__infos__"

echo "Adding metadata info for a connector..."

read -p "In which existing connector?(give connector folder name) " CONNECTOR_NAME

CONNECTOR_DIRECTORY=$(find . -type d -name "$CONNECTOR_NAME")

echo "Found this directory : " "$CONNECTOR_DIRECTORY"

read -p "Is it the correct connector?(y/n) " ANSWER

if [[ "${ANSWER,,}" =~ ('y') ]]; then
	echo "Adding info file for: " "$CONNECTOR_NAME"
	    mkdir -p "$CONNECTOR_DIRECTORY/$CONNECTOR_INFOS_DIRECTORY"

      # create metadata info
      metadata_path=$(find . -name "metadata.json.sample")
      cp "$metadata_path" "$CONNECTOR_DIRECTORY/$CONNECTOR_INFOS_DIRECTORY/connector_infos.json"

      echo "You can complete infos for the connector."

else
	echo "OK, then see you :)"
fi