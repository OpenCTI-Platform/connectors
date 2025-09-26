#!/bin/sh

# Check required environment variables
if [ -z "$OPENCTI_URL" ]; then
    echo "[ERROR] OPENCTI_URL environment variable is not set"
    exit 1
fi

if [ -z "$OPENCTI_TOKEN" ]; then
    echo "[ERROR] OPENCTI_TOKEN environment variable is not set"
    exit 1
fi

if [ -z "$CONNECTOR_ID" ]; then
    echo "[ERROR] CONNECTOR_ID environment variable is not set"
    exit 1
fi

if [ -z "$MISP_URL" ]; then
    echo "[ERROR] MISP_URL environment variable is not set"
    exit 1
fi

if [ -z "$MISP_API_KEY" ]; then
    echo "[ERROR] MISP_API_KEY environment variable is not set"
    exit 1
fi

# Check OpenCTI connectivity (optional)
if command -v curl >/dev/null 2>&1; then
    echo "[INFO] Checking OpenCTI connectivity..."
    if curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $OPENCTI_TOKEN" "$OPENCTI_URL/graphql" | grep -q "200\|400"; then
        echo "[INFO] Successfully connected to OpenCTI"
    else
        echo "[WARNING] Could not verify OpenCTI connectivity, continuing anyway..."
    fi
else
    echo "[INFO] curl not available, skipping connectivity check"
fi

# Change to the connector directory
cd /opt/opencti-connector-misp-intel || exit 1

# Start the connector
echo "[INFO] Starting MISP Intel Stream Connector..."
exec python3 main.py
