FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
WORKDIR /opt/opencti-connector-mokn

# Copy the connector
COPY src /opt/opencti-connector-mokn

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Run as non-root user
RUN adduser -D -H -s /bin/sh connector && \
    chown -R connector:connector /opt/opencti-connector-mokn

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
USER connector
ENTRYPOINT ["/entrypoint.sh"]
