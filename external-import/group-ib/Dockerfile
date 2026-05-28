FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector
COPY src /opt/connector/src
WORKDIR /opt/connector/src

RUN pip3 install --no-cache-dir -r /opt/connector/src/requirements.txt
RUN rm -rf /var/cache/apk/*

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
