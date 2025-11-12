#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-virustotal-livehunt-stream

# Launch the worker
python3 virustotal_livehunt.py
