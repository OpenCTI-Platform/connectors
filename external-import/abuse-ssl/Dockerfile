FROM python:3.11-alpine

# Copy the connector
COPY src /opt/opencti-abuse-ssl

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libxslt libxslt-dev libxml2 libxml2-dev && \
    cd /opt/opencti-abuse-ssl && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

