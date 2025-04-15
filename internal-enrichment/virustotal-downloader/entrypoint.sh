#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-virustotal-downloader

# Launch the worker
python3 virustotal-downloader.py
