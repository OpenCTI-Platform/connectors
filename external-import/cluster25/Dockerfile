FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY requirements.txt /opt/opencti-connector-cluster25/

RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-cluster25 && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

# Copy the connector
COPY src /opt/opencti-connector-cluster25

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
