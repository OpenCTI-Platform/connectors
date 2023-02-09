FROM python:3.10-alpine

# Copy the connector
COPY src /opt/opencti-connector-import-file-stix

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-import-file-stix && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base gfortran musl-dev g++ openblas openblas-dev

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
