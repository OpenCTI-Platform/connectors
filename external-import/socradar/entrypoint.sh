#!/bin/sh

# Add debugging information
echo "Current directory: $(pwd)"
echo "Python path: $PYTHONPATH"

# Go to the right directory
cd /opt/opencti-connector-socradar

# Launch the worker
python3 main.py