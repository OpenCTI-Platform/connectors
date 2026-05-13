FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-cybelangel
WORKDIR /opt/opencti-connector-cybelangel

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libxslt libxslt-dev libxml2 libxml2-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base libxslt-dev libxml2-dev

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
