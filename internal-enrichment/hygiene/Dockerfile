FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the worker
COPY src /opt/opencti-connector-hygiene/src
WORKDIR /opt/opencti-connector-hygiene
# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev rust cargo openssl-dev

RUN cd /opt/opencti-connector-hygiene/src && \
    pip3 install --no-cache-dir -r /opt/opencti-connector-hygiene/src/requirements.txt && \
    apk del git build-base rust cargo openssl-dev && \
    rm -rf /var/cache/apk/*

CMD ["python", "-m", "src"]