FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-polyswarm-sandbox/src
WORKDIR /opt/opencti-connector-polyswarm-sandbox/src

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-polyswarm-sandbox/src && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del --no-network git build-base

# Entrypoint
ENTRYPOINT ["python", "main.py"]
