#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-export-file-csv

# Launch the worker
python3 export-file-csv.py
