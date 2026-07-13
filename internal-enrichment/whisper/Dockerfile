FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT
# Stream logs immediately so startup/connection-retry messages are visible.
ENV PYTHONUNBUFFERED=1

# Copy the connector
COPY src /opt/opencti-connector-whisper

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-whisper && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Exec-form ENTRYPOINT, no shell wrapper — the upstream Verified linter
# (VC402) forbids an entrypoint.sh shim. python is PID 1 either way, so
# SIGTERM from `docker stop` still reaches the connector directly.
WORKDIR /opt/opencti-connector-whisper
ENTRYPOINT ["python", "main.py"]
