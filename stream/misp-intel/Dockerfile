FROM python:3.11-alpine
ENV CONNECTOR_TYPE=STREAM

# Copy the connector source code
COPY src /opt/opencti-connector-misp-intel

# Install system dependencies
RUN apk update && \
    apk add --no-cache git build-base libffi-dev libxml2-dev libxslt-dev && \
    apk add --no-cache curl jq

# Install Python dependencies
WORKDIR /opt/opencti-connector-misp-intel
RUN pip3 install --no-cache-dir -r requirements.txt

# Create non-root user
RUN addgroup -S connector && \
    adduser -S connector -G connector && \
    chown -R connector:connector /opt/opencti-connector-misp-intel

# Copy entrypoint script
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Switch to non-root user
USER connector

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]
