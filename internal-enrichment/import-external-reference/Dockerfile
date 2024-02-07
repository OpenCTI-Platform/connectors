FROM python:3.11-bullseye
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-import-external-reference

# Install Python modules
# hadolint ignore=DL3003
RUN apt-get update && \
    apt-get install -y git build-essential libmagic-dev libffi-dev libxml2-dev libxslt-dev libssl-dev cargo libjpeg-dev zlib1g-dev && \
    ARCH=`echo -n $(uname -m) | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/'` && \
        wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_${ARCH}.deb && \
        apt-get install -y ./wkhtmltox_0.12.6.1-2.bullseye_${ARCH}.deb && \
        rm wkhtmltox_0.12.6.1-2.bullseye_${ARCH}.deb && \
    cd /opt/opencti-connector-import-external-reference && \
    pip3 install --no-cache-dir -r requirements.txt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
