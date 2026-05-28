FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-alienvault

RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-alienvault && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*


# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
