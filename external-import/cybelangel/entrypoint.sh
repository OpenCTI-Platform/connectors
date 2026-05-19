#!/bin/sh
set -e

# Correct working directory
cd /opt/opencti-connector-cybelangel

# Replace the shell with the Python process so it receives SIGTERM/SIGINT
# directly and Docker can perform a graceful shutdown.
exec python3 cybelangel.py
