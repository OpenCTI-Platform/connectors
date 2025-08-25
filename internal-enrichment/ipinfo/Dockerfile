FROM python:3.13-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/connector/src
WORKDIR /opt/connector

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/connector/src && \
    pip3 install --no-cache-dir -r /opt/connector/src/requirements.txt && \
    apk del git build-base

CMD ["python", "-m", "src"]
