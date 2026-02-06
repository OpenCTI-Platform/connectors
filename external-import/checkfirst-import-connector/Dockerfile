FROM python:3.12-alpine

WORKDIR /opt/opencti-connector-checkfirst-import-connector

# System deps
# - ca-certificates: HTTPS/TLS trust store for OpenCTI/API calls
# - libmagic: required by python-magic (pulled by pycti on Linux)
# - libffi: common runtime dep for wheels using libffi
RUN apk add --no-cache \
    ca-certificates \
    libffi \
    libmagic

COPY src /opt/opencti-connector-checkfirst-import-connector
# Build deps (removed after pip install to keep the final image smaller)
RUN apk add --no-cache --virtual .build-deps \
        build-base \
        git \
        libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

ENV PYTHONUNBUFFERED=1

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
