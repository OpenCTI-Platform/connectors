#!/bin/bash

set -eo pipefail # exit on error

generate_manifest=$(find . -name "generate_global_manifest.py")
printf "\nGenerating manifest file...\n"
python "$generate_manifest"

# Ensure manifest is created
manifest_exists=$(find "$(pwd)" -name "manifest.json")

if [ -f "$manifest_exists" ]; then
  echo "✅- Manifest well created !"
else
  echo "❌- Manifest not created !"
fi

