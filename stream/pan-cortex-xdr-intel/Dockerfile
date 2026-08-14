FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-connector-pan-cortex-xdr-intel
WORKDIR /opt/opencti-connector-pan-cortex-xdr-intel

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-pan-cortex-xdr-intel && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

ENTRYPOINT ["python3", "main.py"]
