#!/bin/sh
# Fail fast on any error so the container does not silently accept export
# jobs that are guaranteed to fail later when ``ODS_Standard`` tries to
# connect to a missing / dead LibreOffice listener.
set -eu

cd /opt/opencti-connector-export-file-ods

# Start the headless LibreOffice listener required by ``unogenerator`` so that
# the Python UNO bridge can connect to it. ``unogenerator_start`` exits
# non-zero when the command is missing, when LibreOffice fails to start or
# when the configured UNO port is already in use; thanks to ``set -e``
# above the entrypoint then aborts immediately instead of starting the
# worker against a non-functional listener.
if ! command -v unogenerator_start >/dev/null 2>&1; then
    echo "FATAL: 'unogenerator_start' is not on PATH; cannot start the LibreOffice listener." >&2
    exit 1
fi
unogenerator_start

# Launch the worker (replaces the shell so PID 1 is the connector).
exec python3 main.py
