FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV PYTHONUNBUFFERED=1

RUN apk update && apk upgrade && \
    apk add --no-cache \
        libmagic \
        p7zip \
        libarchive-tools \
        gcc \
        musl-dev \
        libffi-dev \
        openssl-dev \
        libxml2-dev \
        libxslt-dev && \
    apk add --virtual .build-deps git && \
    rm -rf /var/cache/apk/*

COPY src/requirements.txt /opt/opencti-connector/
WORKDIR /opt/opencti-connector

RUN pip install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

COPY src/ /opt/opencti-connector/

RUN adduser -D connector
USER connector

ENTRYPOINT ["/entrypoint.sh"]
