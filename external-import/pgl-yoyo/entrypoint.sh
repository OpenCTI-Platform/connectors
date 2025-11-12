#!/bin/sh
set -euo pipefail

# Go to the right directory
cd /opt/opencti-connector

# Launch the worker
python3 main.py