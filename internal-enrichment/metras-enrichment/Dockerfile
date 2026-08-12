FROM python:3.12-alpine

ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY src /opt/opencti-connector-metras-enrichment

RUN apk update && apk upgrade --no-cache && \
    apk --no-cache add libmagic libffi libxml2 libxslt && \
    apk --no-cache add --virtual .build-deps git build-base libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-metras-enrichment && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh && \
    adduser -D -u 1000 connector && \
    chown -R connector:connector /opt/opencti-connector-metras-enrichment
USER connector

ENTRYPOINT ["/entrypoint.sh"]
