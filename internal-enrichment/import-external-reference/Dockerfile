FROM python:3.11-bullseye
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-import-external-reference

# Install Python modules
# hadolint ignore=DL3003
RUN apt-get update && \
    apt-get install -y git build-essential libmagic-dev libffi-dev libxml2-dev libxslt-dev libssl-dev cargo libjpeg-dev zlib1g-dev libxkbcommon0 libgbm1  && \
    cd /opt/opencti-connector-import-external-reference && \
    pip3 install --no-cache-dir -r requirements.txt && \
    playwright install

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
