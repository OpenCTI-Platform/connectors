#!/usr/bin/env sh
set -eu

cd /opt/opencti-connector-checkfirst-import-connector
exec python3 main.py
