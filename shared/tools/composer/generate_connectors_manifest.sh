#!/bin/bash

set -euo pipefail  # exit on error

generate_manifest=$(find . -name "generate_connectors_manifest.py")
echo -e "\nGenerating manifest file..."
python "$generate_manifest"

# Ensure manifest is created
manifest_exists=$(find "$(pwd)" -name "manifest.json")

if [ -f "$manifest_exists" ]; then
  echo "✅- Manifest well created !"
else
  echo "❌- Manifest not created !"
fi

