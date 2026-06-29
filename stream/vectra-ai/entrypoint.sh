#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-vectra-ai

# Launch the worker as PID 1 so it receives container signals (e.g. SIGTERM) directly
exec python3 main.py
