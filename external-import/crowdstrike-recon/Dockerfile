FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-crowdstrike-recon

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add libmagic libffi libxml2 libxslt && \
    apk --no-cache add --virtual .build-deps git build-base libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-crowdstrike-recon && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
