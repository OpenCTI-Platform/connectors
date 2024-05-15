FROM python:3.11-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-crowdsec

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-crowdsec && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

