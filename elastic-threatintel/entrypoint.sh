#!/bin/bash
set -e

if [ $# -eq 0 ]; then
  # Default case of no args
  set -- /app/connector-elastic-threatintel
elif [ "${1:0:1}" = '-' ]; then
  # If the user is trying to run connector directly with some arguments, then
  # pass them along.
    set -- /app/connector-elastic-threatintel "$@"
elif [ $# -gt 0 ]; then
  # Run whatever command the user wanted
  exec "$@"
fi

cd /app
exec "$@"
