#!/bin/sh

# Hand off to the connector worker. ``exec`` replaces the shell with
# the Python process so signals (SIGTERM from Docker on container
# stop, SIGINT from kubectl) reach PID 1 directly and the connector
# can shut down gracefully.
exec python3 src/main.py
