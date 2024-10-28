FROM python:3.12-bookworm
# Browser builds for Firefox and WebKit are built for the glibc library. Alpine Linux and other distributions that are based on the musl standard library are not supported.
# https://playwright.dev/python/docs/docker#alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-import-external-reference

# Install Python modules
# hadolint ignore=DL3003
RUN apt-get update && \
    apt-get install -y git build-essential libmagic-dev libffi-dev libxml2-dev libxslt-dev libssl-dev cargo libjpeg-dev zlib1g-dev libxkbcommon0 libgbm1 libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libatspi2.0-0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libasound2 && \
    cd /opt/opencti-connector-import-external-reference && \
    pip3 install --no-cache-dir -r requirements.txt && \
    playwright install

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]


