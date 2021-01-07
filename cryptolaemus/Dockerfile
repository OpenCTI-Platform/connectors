FROM python:3.8-alpine

# Copy the connector
COPY src /opt/opencti-connector-cryptolaemus

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libxml2 libxslt-dev && \
    cd /opt/opencti-connector-cryptolaemus && \
    pip3 install --no-cache-dir git+https://github.com/OpenCTI-Platform/client-python@4.0.5 && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
