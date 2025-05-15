FROM python:3.12-alpine as silentpush-enrichment

LABEL authors="jorgeley@silentpush.com"

ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT
ENV CONNECTOR_SCOPE=Indicator,URL,IPv4-Addr,IPv6-Addr,Domain-Name,Hostname

# Copy the connector
COPY src /opt/silentpush-enrichment

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/silentpush-enrichment && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
