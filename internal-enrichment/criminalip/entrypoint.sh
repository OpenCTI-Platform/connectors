#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] Starting Criminal IP connector skeleton..."
python -u src/criminalipImport.py
