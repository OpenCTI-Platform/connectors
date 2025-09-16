FROM python:3.13-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-cve/src
WORKDIR /opt/opencti-connector-cve

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev

RUN cd /opt/opencti-connector-cve/src && \
    pip3 install --no-cache-dir -r /opt/opencti-connector-cve/src/requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

CMD ["python", "-m", "src"]
