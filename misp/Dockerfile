FROM python:3.7.4-alpine3.10

# Copy the connector
COPY src /opt/opencti-connector-misp

# Install Python modules
RUN BUILD_MISP=noninteractive \
    apk add build-base && \
    cd /opt/opencti-connector-misp && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
