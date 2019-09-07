FROM python:3.7.4-alpine3.10

# Copy the connector
COPY src /opt/opencti-connector-cve

# Install Python modules
RUN BUILD_CVE=noninteractive \
    apk add build-base && \
    cd /opt/opencti-connector-cve && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
