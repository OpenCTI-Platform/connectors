#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-elasticsearch

# Launch the worker
python3 elasticsearch_connector.py
