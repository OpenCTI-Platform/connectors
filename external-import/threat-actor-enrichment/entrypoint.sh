#!/bin/sh
set -e

cd /opt/opencti-connector-threat-actor-enrichment

exec python3 main.py
