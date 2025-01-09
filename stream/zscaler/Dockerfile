FROM python:3.11-alpine

ENV CONNECTOR_TYPE=STREAM

# Copy the worker
COPY src /opt/opencti-connector-zscaler

# Install Python modules and dependencies
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-zscaler && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]