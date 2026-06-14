#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-matrix

# Launch the worker
exec python3 main.py
