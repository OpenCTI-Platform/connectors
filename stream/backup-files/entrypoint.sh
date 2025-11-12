#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-backup-files

# Launch the worker
python3 backup-files.py
