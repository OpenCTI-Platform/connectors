FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV PYTHONUNBUFFERED=1

RUN apk --no-cache upgrade && \
    apk add --no-cache \
        brotli-libs \
        libmagic \
        p7zip \
        libarchive-tools \
        libffi \
        libxml2 \
        libxslt && \
    apk add --no-cache --virtual .build-deps \
        git \
        gcc \
        musl-dev \
        libffi-dev \
        openssl-dev \
        libxml2-dev \
        libxslt-dev && \
    rm -rf /var/cache/apk/*

COPY src/requirements.txt /opt/opencti-connector/
WORKDIR /opt/opencti-connector

# The Pillow wheels bundle Brotli 1.2.0 (CVE-2026-111497) for FreeType: in the
# same layer, replace the bundled libbrotlidec with a link to the system one
# (brotli-libs, fixed) and remove the bundled libbrotlicommon, which only it
# loads (#8108).
# The link keeps the bundled name (libbrotlidec-<hash>.so.1.2.0), the one
# FreeType loads, but resolves to the system version.
RUN pip install --no-cache-dir -r requirements.txt && \
    cd /usr/local/lib/python3*/site-packages/pillow.libs && \
    rm libbrotlicommon-* && \
    ln -sf /usr/lib/libbrotlidec.so.1 libbrotlidec-* && \
    apk del .build-deps

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

COPY src/ /opt/opencti-connector/

RUN adduser -D connector
USER connector

ENTRYPOINT ["/entrypoint.sh"]
