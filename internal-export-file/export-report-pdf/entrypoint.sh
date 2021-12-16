#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-export-report-pdf

# Launch the worker
python3 export-report-pdf.py
