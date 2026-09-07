FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY spycloud_connector /opt/spycloud_connector
COPY pyproject.toml /opt/pyproject.toml
COPY main.py /opt/main.py
# Entry script runs from /opt, so this is where pycti looks for the version.
COPY __metadata__/connector_manifest.json /opt/__metadata__/connector_manifest.json

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt && \
    pip3 install --no-cache-dir . && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
