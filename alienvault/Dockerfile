FROM python:3.7.6-alpine3.11

# Copy the connector
COPY src /opt/opencti-connector-alienvault

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache update && apk upgrade && \
    apk --no-cache add git build-base libmagic && \
    cd /opt/opencti-connector-alienvault && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir antlr4-python3-runtime==4.7.2 && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
