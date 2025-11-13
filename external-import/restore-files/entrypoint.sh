#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-restore-files

# Launch the worker
python3 restore-files.py
