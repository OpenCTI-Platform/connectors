FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-import-external-reference

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic-dev libffi-dev libxml2-dev libxslt-dev libssl-dev cargo libjpeg-dev zlib1g-dev libxkbcommon0 libgbm1 libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libatspi2.0-0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libasound2 && \
    cd /opt/opencti-connector-import-external-reference && \
    pip3 install --no-cache-dir -r requirements.txt && \
    playwright install && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]


