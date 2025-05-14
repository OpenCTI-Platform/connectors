FROM python:3.12-alpine

ENV CONNECTOR_TYPE=INTERNAL_IMPORT_FILE

# Copy the connector
COPY src /opt/opencti-connector-import-document-ai

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev libffi-dev openssl-dev rust cargo && \
    cd /opt/opencti-connector-import-document-ai && \
    pip3 install --no-cache-dir -r requirements.txt 

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh && chmod -R 0777 /opt/opencti-connector-import-document-ai
WORKDIR /opt/opencti-connector-import-document-ai
ENV HOME=/opt/opencti-connector-import-document-ai
ENTRYPOINT ["/entrypoint.sh"]
