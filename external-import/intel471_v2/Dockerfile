FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-intel471_v2

# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libxslt libxslt-dev libxml2 libxml2-dev && \
    cd /opt/opencti-intel471_v2 && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
