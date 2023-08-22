FROM python:3.11-alpine

# Copy the connector
COPY src /opt/opencti-connector-import-url-to-report

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev gfortran musl-dev g++ openblas openblas-dev && \
    cd /opt/opencti-connector-import-url-to-report && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base gfortran musl-dev g++ openblas-dev

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
