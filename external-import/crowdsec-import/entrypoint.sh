#!/bin/sh

# Correct working directory
cd /opt/opencti-crowdsec-import || exit

# Start the connector
python3 main.py

