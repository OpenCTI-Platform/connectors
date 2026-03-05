FROM python:3.11-alpine

ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector source
COPY src /opt/opencti-connector-ismalicious

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-ismalicious && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
WORKDIR /opt/opencti-connector-ismalicious
ENTRYPOINT ["python3", "main.py"]
