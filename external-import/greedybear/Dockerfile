FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-connector-greedybear

RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev procps

RUN cd /opt/opencti-connector-greedybear && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Run as an unprivileged user
RUN addgroup -S connector && adduser -S -G connector connector && \
    chown -R connector:connector /opt/opencti-connector-greedybear
USER connector

# Liveness: the connector long-running process must be present
HEALTHCHECK --interval=5m --timeout=10s --start-period=30s --retries=3 \
    CMD pgrep -f main.py > /dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
