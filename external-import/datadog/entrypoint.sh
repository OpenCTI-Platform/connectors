#!/bin/sh

cd /opt/opencti-connector-datadog || exit 1

exec python3 connector.py
