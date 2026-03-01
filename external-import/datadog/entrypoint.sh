#!/bin/sh

# Correct working directory
cd /opt/opencti-connector-datadog-import || exit 1

# Start the connector
python connector.py
