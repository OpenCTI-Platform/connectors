#!/bin/bash
set -e

# Load runtime
. /runtime/bin/activate

if [ $# -eq 0 ]; then
  # Default case of no args
  set -- /runtime/bin/elastic
elif [ "${1:0:1}" = '-' ]; then
  # If the user is trying to run the connector directly with some arguments,
  # then pass them along.
    set -- /runtime/bin/elastic "$@"
elif [ $# -gt 0 ]; then
  # Run whatever command the user wanted
  exec "$@"
fi

exec "$@"
