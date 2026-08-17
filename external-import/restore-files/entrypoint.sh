#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-restore-files

# Launch the worker
python3 restore-files.py

# Pause before exiting if requested
[ "0$BACKUP_POLL_FREQUENCY" -gt 0 ] 2>/devnull && /bin/sleep "$BACKUP_POLL_FREQUENCY"
