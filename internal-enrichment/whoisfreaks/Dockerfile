FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-whoisfreaks/src
WORKDIR /opt/opencti-connector-whoisfreaks

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-whoisfreaks/src && \
    pip3 install --no-cache-dir -r /opt/opencti-connector-whoisfreaks/src/requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

CMD ["python3", "src/main.py"]
