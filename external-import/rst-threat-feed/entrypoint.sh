#!/bin/sh
set -e
cd /opt/opencti-connector-rst-threat-feed
exec python3 src/main.py
