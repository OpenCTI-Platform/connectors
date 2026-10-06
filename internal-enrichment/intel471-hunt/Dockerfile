FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-intel471-hunt/src
COPY pyproject.toml README.md config.yml.sample /opt/opencti-connector-intel471-hunt/
WORKDIR /opt/opencti-connector-intel471-hunt

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN pip3 install --no-cache-dir . && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

# The cache lives on a dedicated subdirectory so a mounted volume never shadows
# the connector code in the working directory.
RUN mkdir -p /opt/opencti-connector-intel471-hunt/cache

CMD ["python", "-m", "src"]
