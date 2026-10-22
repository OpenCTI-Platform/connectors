FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-connector-dectrax

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-dectrax && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["sh", "/entrypoint.sh"]
