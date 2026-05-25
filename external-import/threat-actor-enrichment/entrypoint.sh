#!/bin/sh
set -e

cd /opt/opencti-connector-threat-actor-enrichment

exec python3 threat_actor_enrichment.py
