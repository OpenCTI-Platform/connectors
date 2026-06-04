FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV PYTHONUNBUFFERED=1

RUN addgroup -S connector && adduser -S connector -G connector

RUN apk update && \
    apk add --no-cache --virtual .build-deps git build-base libffi-dev && \
    apk add --no-cache libmagic && \
    rm -rf /var/cache/apk/*

COPY src/requirements.txt /opt/opencti-connector/
WORKDIR /opt/opencti-connector

RUN pip install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

COPY src/ /opt/opencti-connector/
COPY entrypoint.sh /

RUN chmod +x /entrypoint.sh

USER connector

ENTRYPOINT ["/entrypoint.sh"]
