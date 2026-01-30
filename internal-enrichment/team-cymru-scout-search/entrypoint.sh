#!/bin/sh
set -e

# Run vocabulary setup script
echo "Setting up vocabulary pattern type..."
python3 /opt/scout-search-connector/setup_pattern_type.py

# Start the connector
echo "Starting Scout Search Connector..."
cd /opt/scout-search-connector
python3 -m src.scout_search_connector.main