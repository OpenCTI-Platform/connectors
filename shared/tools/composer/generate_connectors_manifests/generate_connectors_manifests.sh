#!/bin/bash

set -eo pipefail  # exit on error

echo "In order to run, this script needs to install the following python package: mistune."
echo "Please double-check that you are in a virtual env, or it will install this dependency globally."
read -p "Do you want to continue? (y/n) " ANSWER

# Convert input to lowercase (compatible with bash 3.2)
ANSWER_LOWER=$(echo "$ANSWER" | tr '[:upper:]' '[:lower:]')

if [[ ! "$ANSWER_LOWER" =~ ^y ]]; then
    echo "OK, then see you :)"
    exit 0
fi

pip install mistune

generate_manifests=$(find . -name "generate_connectors_manifests.py")
echo ""
echo "Generating connectors' manifests files..."
python "$generate_manifests"

echo "The script has run successfully, please check that no connectors have been skipped due to errors."
echo "You can now safely uninstall the following python package: mistune."
 