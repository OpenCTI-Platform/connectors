#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-export-file-txt

# Launch the worker
python3 export-file-txt.py
