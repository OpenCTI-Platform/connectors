#!/bin/bash

set -euo pipefail  # exit on error

generate_manifests=$(find . -name "generate_connectors_manifests.py")
echo -e "\nGenerating connectors' manifests files..."
python "$generate_manifests"


