#!/bin/sh

# Start libreoffice as a service
unogenerator_start
# Start the connector (WORKDIR is /opt/connector as set in the Dockerfile)
python3 main.py
