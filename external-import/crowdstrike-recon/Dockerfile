FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-crowdstrike-recon

# Install Python modules
# Build deps are added, used and removed in a single RUN layer so the build
# headers do not persist in an earlier image layer.
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add libmagic libffi libxml2 libxslt && \
    apk --no-cache add --virtual .build-deps git build-base libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-crowdstrike-recon && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Entrypoint
WORKDIR /opt/opencti-connector-crowdstrike-recon
ENTRYPOINT ["python3", "main.py"]
