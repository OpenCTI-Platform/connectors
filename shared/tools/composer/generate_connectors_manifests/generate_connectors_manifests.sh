#!/bin/bash

set -euo pipefail  # exit on error

echo -e "In order to run, this script needs to install the following python package: mistune."
echo -e "Please double-check that you are in a virtual env, or it will install this dependency globally."
read -p "Do you want to continue? (y/n) " ANSWER
if [[ ! "${ANSWER,,}" =~ ^y ]]; then
    echo "OK, then see you :)"
    exit 0
fi

pip install mistune

generate_manifests=$(find . -name "generate_connectors_manifests.py")
echo -e "\nGenerating connectors' manifests files..."
python "$generate_manifests"

echo -e "The script has run successfully, please check that no connectors have been skipped due to errors."
echo -e "You can now safely uninstall the following python package: mistune."
