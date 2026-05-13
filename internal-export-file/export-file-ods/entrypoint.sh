#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-export-file-ods

# Start the headless LibreOffice listener required by ``unogenerator`` so that
# the Python UNO bridge can connect to it.
unogenerator_start

# Launch the worker
exec python3 main.py
