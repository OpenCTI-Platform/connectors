#!/bin/sh

# Correct working directory
cd /opt/opencti-crowdsec || exit

pip3 install --no-cache-dir -r requirements.txt

# Idle indefinitely
while true; do
    sleep 60 # Sleeps for 60 seconds and then loops again
done