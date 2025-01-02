FROM python:3.11-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-ioclookup

# Install dependencies
RUN apk --no-cache add git build-base libmagic && \
    cd /opt/opencti-connector-ioclookup && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
