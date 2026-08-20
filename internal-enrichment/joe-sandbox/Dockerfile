FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-joe-sandbox
WORKDIR /opt/opencti-connector-joe-sandbox

# Install Python modules
# Build deps go in a virtual package that is added, used, and removed within a
# single RUN layer so the published image never permanently retains the build
# toolchain. libmagic / libffi are kept as runtime dependencies.
# hadolint ignore=DL3003
RUN apk --no-cache add libmagic libffi-dev && \
    apk --no-cache add --virtual .build-deps git build-base && \
    cd /opt/opencti-connector-joe-sandbox && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del .build-deps && \
    rm -rf /var/cache/apk/*

CMD ["python", "main.py"]
