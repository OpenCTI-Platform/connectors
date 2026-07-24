#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-import-document-llm

# Launch the worker. OCR models are loaded lazily only if a document requires OCR.
exec python3 main.py
