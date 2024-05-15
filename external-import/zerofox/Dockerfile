FROM python:3.11-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install necessary packages
# hadolint ignore=DL3003
RUN apk update && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy only requirements.txt first to leverage Docker cache
COPY src/requirements.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    apk del git build-base

# Copy the connector
COPY src /opt/opencti-connector-zerofox
# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
