#!/bin/sh
set -e

cd /opt/opencti-connector-cvelistv5
exec python3 main.py
