#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-export-file-stix

# Launch the worker
python3 export-file-stix.py
