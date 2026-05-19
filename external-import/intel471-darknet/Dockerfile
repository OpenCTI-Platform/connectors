FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector source.
COPY src /opt/opencti-connector-intel471-darknet

# Install the Python modules required at runtime. The compiler toolchain
# and the ``*-dev`` headers needed to build the wheels are installed via
# an Alpine "virtual" package (``.build-deps``) so the **whole** set of
# build-only files — ``build-base``, ``git``, ``libffi-dev``,
# ``libxml2-dev``, ``libxslt-dev`` and the transitively-pulled headers —
# is removed with a single ``apk del .build-deps`` in the same RUN
# layer. Runtime-only libraries (``libmagic``) are installed
# unconditionally and stay in the published image.
# hadolint ignore=DL3018,DL3003
RUN apk --no-cache add libmagic && \
    apk add --no-cache --virtual .build-deps \
        build-base \
        git \
        libffi-dev \
        libxml2-dev \
        libxslt-dev && \
    cd /opt/opencti-connector-intel471-darknet && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Expose and entrypoint.
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
