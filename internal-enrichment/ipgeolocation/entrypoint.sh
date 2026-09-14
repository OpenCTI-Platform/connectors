#!/bin/bash
set -e

cd /opt/opencti-connector
exec python -m src.main
