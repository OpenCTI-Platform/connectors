FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-noisecontrol

# Install dependencies
RUN apk --no-cache add git build-base libmagic && \
    cd /opt/opencti-connector-noisecontrol && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
